# Кто там?
SSH сервис, который знает кто вы.

## Попробуйте (это безопасно)

~~ssh whoami.shanginn.ru~~
Временно не работает.

## Как это работает

При подключении к SSH серверу, вы шлёте все свои публичные ключи один за одним, пока
сервер не примет какой-нибудь. Кто-нибудь может воспользоваться этим и записать
все публичные ключи клиента.

Ещё один факт: GitHub позволяет любому получить доступ к публичным ключам пользователей.
Ben Cox [собрал все ключи](https://blog.benjojo.co.uk/post/auditing-github-users-keys), но
я не смог нигде найти готовую базу, поэтому пришлось
[создавать свою](https://github.com/shanginn/github_public_keys_database).

Больше информации вы сможете найти [у автора этого сервера](https://github.com/FiloSottile/whosthere).

## Как запустить

Для начала скачайте, распакуйте и залейте в mysql [базу ключей](https://yadi.sk/d/TjeKTLOG3E8Xgt).

Затем идите в `./src/sshserver/`.

```bash
mv config.dist.yml config.yml
```

- HostKey: Сгенерируйте приватный ключ для своего сервера (ssh-keygen) и вставьте его туда
- GitHubId: Ваш ID на гитхабе (https://api.github.com/users/USERNAME)
- GitHubSecret: oAuth токен (https://developer.github.com/v3/oauth/)
- MySQL: Параметры подключения к mysql серверу в формате `user:pass@server/db_name`,
например подключение через сокет `mysql_user:MYPASSWORD@unix(/var/lib/mysql/mysql.sock)/github_keys_db`
- Listen: Порт на котором будет работать ssh сервер.

После настройки(хотя можно было и перед) делаем

```bash
go build
```

И запускаем `./sshserver`

Может появиться сообщение, типа

```
2016/12/09 06:50:32 listen tcp :80: bind: permission denied
```

Не обращайте внимания, я не знаю, что это :)

Возможно, нужно установить какие-то зависимости, но я этого уже не помню.

## Как это остановить?

Добавьте эти строки в конец `~/.ssh/config` (После всех "Host"),
либо пропишите это в `/etc/ssh/ssh_config`

```
Host *
    PubkeyAuthentication no
    IdentitiesOnly yes
```

А потом укажите, какие именно ключи должны использоваться для хоста

```
Host example.com
    PubkeyAuthentication yes
    IdentityFile ~/.ssh/id_rsa
    # IdentitiesOnly yes # Enable ssh-agent (PKCS11 etc.) keys
```

Лучше использовать разные ключи для разных хостов

```
Host github.com
    PubkeyAuthentication yes
    IdentityFile ~/.ssh/github_id_rsa
```

## Донат

Если вам понравилось, то сперва угостите [автора оригинально идеи](https://github.com/FiloSottile/whosthere),
а потом и меня :)

bitcoin:1H7GXLYRXieWCXB3NomXC9P1M8w3iK4n9Y
