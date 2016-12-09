package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"text/template"
	"time"

	"github.com/google/go-github/github"
	"golang.org/x/crypto/ssh"
)

var termTmpl = template.Must(template.New("termTmpl").Parse(strings.Replace(`
    +---------------------------------------------------------------------+
    |                                                                     |
    |             _o/ Привет, {{ .Name }}!                                |
    |                                                                     |
    |                                                                     |
    |  Вы знали, что ssh отправляет все ваши публичные ключи              |
    |  любому серверу, на котором вы пытаетесь аутентифицироваться?       |
    |                                                                     |
    |  Так мы узнали, что вы @{{ .User }} на GitHub!                      |
    |                                                                     |
    |  Может быть вы не знали, что GitHub публикует публичные ключи       |
    |  всех пользователей? И я всех их собрал и опубликовал.              |
    |                                                                     |
    |  Иногда это очень удобно :) Например, ваши ключи лежат здесь        |
    |  https://github.com/{{ .User }}.keys                                |
    |                                                                     |
    |                                                                     |
    |  P.S.   Весь код открыт (И написан Go!)                             |
    |  https://github.com/shanginn/whosthere                              |
    |                                                                     |
    |  P.P.S  Оригинальная идея:                                          |
    |  https://github.com/FiloSottile/whosthere                           |
		|                                                                     |
    |  -- @shanginn (https://twitter.com/shanginn)                        |
    |                                                                     |
    +---------------------------------------------------------------------+

`, "\n", "\n\r", -1)))

var failedMsg = []byte(strings.Replace(`
    +---------------------------------------------------------------------+
    |                                                                     |
    |             _o/ Привет!                                             |
    |                                                                     |
    |                                                                     |
    |  Вы знали, что ssh  отправляет все ваши публичные ключи             |
    |  любому серверу, на котором вы пытаетесь аутентифицироваться?       |
    |                                                                     |
    |  Мы пытались найти вас на GitHub, но не смогли :(                   |
    |  Может у вас вообще нет ssh ключей для GitHub?                      |
    |                                                                     |
    |  Кстати, а вы знали, что GitHub публикует публичные ключи           |
    |  всех пользователей? И я всех их собрал и опубликовал.              |
    |                                                                     |
    |  Иногда это очень удобно :) Но не в этот раз :(                     |
    |                                                                     |
    |                                                                     |
    |  P.S.   Весь код открыт (И написан Go!)                             |
    |  https://github.com/shanginn/whosthere                              |
    |                                                                     |
    |  P.P.S  Оригинальная идея:                                          |
    |  https://github.com/FiloSottile/whosthere                           |
    |                                                                     |
    |  -- @shanginn (https://twitter.com/shanginn)                        |
    |                                                                     |
    +---------------------------------------------------------------------+

`, "\n", "\n\r", -1))

var agentMsg = []byte(strings.Replace(`
                      ***** WARNING ***** WARNING *****

         У вас включен(по умолчанию?) SSH agent forwarding. Это ОЧЕНЬ
      ПЛОХАЯ идея. Например, сейчас у меня есть доступ к вашему ssh-агенту
    и могу использовать ваши ключи как захочу до тех пор, пока вы  подключены.
                Но я хороший парень и не буду ничего с ними делать.
         НО ЛЮБОЙ СЕРВЕР К КОТОРОМУ ВЫ ПОДКЛЮЧЕНЫ И КТО УГОДНО С ROOT-ПРАВАМИ
                НА ЭТОМ СЕРВЕРЕ МОЖЕТ ЛОГИНИТЬСЯ ЗА ВАС ГДЕ УГОДНО!

                       Больше информации:  http://git.io/vO2A6
`, "\n", "\n\r", -1))

var x11Msg = []byte(strings.Replace(`
                      ***** WARNING ***** WARNING *****

         У вас включен(по умолчанию?) X11 forwarding. Это ОЧЕНЬ ПЛОХАЯ идея.
             Например, сейчас у меня есть доступ к вашему X11 серверу
                 	и я могу получить доступ к вашему компьютеру,
                        До тех пор, пока вы подключены.
                Но я хороший парень и не буду ничего с ними делать.
        НО ЛЮБОЙ СЕРВЕР К КОТОРОМУ ВЫ ПОДКЛЮЧЕНЫ И КТО УГОДНО С ROOT-ПРАВАМИ
            НА ЭТОМ СЕРВЕРЕ МОЖЕТ ПЕРЕХВАТЫВАТЬ НАЖАТИЯ КЛАВИШ И
                        	ИМЕЕТ ДОСТУП К ВАШИМ ОКНАМ!

     Больше информации:  http://www.hackinglinuxexposed.com/articles/20040705.html
`, "\n", "\n\r", -1))

var roamingMsg = []byte(strings.Replace(`
                      ***** WARNING ***** WARNING *****

    	  У вас ключен roaming. Если вы используете OpenSSH, то скорее всего
                    вы уязвимы к атаке CVE-2016-0777.

        ЛЮБОЙ СЕРВЕР К КОТОРОМУ ВЫ ПОДКЛЮЧЕНЫ И КТО УГОДНО С ROOT-ПРАВАМИ
            НА ЭТОМ СЕРВЕРЕ МОЖЕТ ПОЛУЧИТЬ ВАШИ ПРИВАТНЫЕ КЛЮЧИ!

     Установите "UseRoaming no" в секции "Host *" вашего ~/.ssh/config или
     /etc/ssh/ssh_config файла, смените ключи и обновитесь как можно скорее.

Больше информации:  https://www.qualys.com/2016/01/14/cve-2016-0777-cve-2016-0778/openssh-cve-2016-0777-cve-2016-0778.txt
`, "\n", "\n\r", -1))

type sessionInfo struct {
	User string
	Keys []ssh.PublicKey
}

type Server struct {
	githubClient *github.Client
	sshConfig    *ssh.ServerConfig
	sqlQuery     *sql.Stmt

	mu          sync.RWMutex
	sessionInfo map[string]sessionInfo
}

func (s *Server) PublicKeyCallback(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	s.mu.Lock()
	si := s.sessionInfo[string(conn.SessionID())]
	si.User = conn.User()
	si.Keys = append(si.Keys, key)
	s.sessionInfo[string(conn.SessionID())] = si
	s.mu.Unlock()

	// Never succeed a key, or we might not see the next. See KeyboardInteractiveCallback.
	return nil, errors.New("")
}

func (s *Server) KeyboardInteractiveCallback(ssh.ConnMetadata, ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	// keyboard-interactive is tried when all public keys failed, and
	// since it's server-driven we can just pass without user
	// interaction to let the user in once we got all the public keys
	return nil, nil
}

type logEntry struct {
	Timestamp     string
	Username      string
	RequestTypes  []string
	Error         string
	KeysOffered   []string
	GitHub        string
	ClientVersion string
}

func (s *Server) Handle(nConn net.Conn) {
	le := &logEntry{Timestamp: time.Now().Format(time.RFC3339)}
	defer json.NewEncoder(os.Stdout).Encode(le)

	conn, chans, reqs, err := ssh.NewServerConn(nConn, s.sshConfig)
	if err != nil {
		le.Error = "Handshake failed: " + err.Error()
		return
	}
	defer func() {
		s.mu.Lock()
		delete(s.sessionInfo, string(conn.SessionID()))
		s.mu.Unlock()
		time.Sleep(500 * time.Millisecond)
		conn.Close()
	}()
	roaming := false
	go func(in <-chan *ssh.Request) {
		for req := range in {
			le.RequestTypes = append(le.RequestTypes, req.Type)
			if req.Type == "roaming@appgate.com" {
				roaming = true
			}
			if req.WantReply {
				req.Reply(false, nil)
			}
		}
	}(reqs)

	s.mu.RLock()
	si := s.sessionInfo[string(conn.SessionID())]
	s.mu.RUnlock()

	le.Username = conn.User()
	le.ClientVersion = fmt.Sprintf("%x", conn.ClientVersion())
	for _, key := range si.Keys {
		le.KeysOffered = append(le.KeysOffered, string(ssh.MarshalAuthorizedKey(key)))
	}

	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			le.Error = "Channel accept failed: " + err.Error()
			return
		}
		defer channel.Close()

		agentFwd, x11 := false, false
		reqLock := &sync.Mutex{}
		reqLock.Lock()
		timeout := time.AfterFunc(30*time.Second, func() { reqLock.Unlock() })

		go func(in <-chan *ssh.Request) {
			for req := range in {
				le.RequestTypes = append(le.RequestTypes, req.Type)
				ok := false
				switch req.Type {
				case "shell":
					fallthrough
				case "pty-req":
					ok = true

					// "auth-agent-req@openssh.com" and "x11-req" always arrive
					// before the "pty-req", so we can go ahead now
					if timeout.Stop() {
						reqLock.Unlock()
					}

				case "auth-agent-req@openssh.com":
					agentFwd = true
				case "x11-req":
					x11 = true
				}

				if req.WantReply {
					req.Reply(ok, nil)
				}
			}
		}(requests)

		reqLock.Lock()
		if agentFwd {
			channel.Write(agentMsg)
		}
		if x11 {
			channel.Write(x11Msg)
		}
		if roaming {
			channel.Write(roamingMsg)
		}

		user, err := s.findUser(si.Keys)
		if err != nil {
			le.Error = "findUser failed: " + err.Error()
			return
		}

		if user == "" {
			channel.Write(failedMsg)
			for _, key := range si.Keys {
				channel.Write(ssh.MarshalAuthorizedKey(key))
				channel.Write([]byte("\r"))
			}
			channel.Write([]byte("\n\r"))
			return
		}

		le.GitHub = user
		name, err := s.getUserName(user)
		if err != nil {
			le.Error = "getUserName failed: " + err.Error()
			return
		}

		termTmpl.Execute(channel, struct{ Name, User string }{name, user})
		return
	}
}
