semgrep_rule_id,semgrep_rule_short,semgrep_category,semgrep_secret_type,semgrep_severity,semgrep_confidence,languages,example_payload,example_source,detection_regex
secrets.code.hardcoded-secret-key-spec-java.hardcoded-secret-key-spec-java,hardcoded-secret-key-spec-java,code,Static Encryption Key,WARNING,HIGH,java,"new SecretKeySpec(""0123456789abcdef0123456789abcdef"".getBytes(), ""AES"");",manual,
secrets.code.hardcoded-secret-key-spec-kt.hardcoded-secret-key-spec-kt,hardcoded-secret-key-spec-kt,code,Static Encryption Key,WARNING,HIGH,kotlin,"val key = SecretKeySpec(""0123456789abcdef0123456789abcdef"".toByteArray(), ""AES"")",manual,
secrets.generic.api-key.python-string.python-string,python-string,generic,Generic Secret,WARNING,HIGH,python,"api_key = ""abc123def456ghi789jkl012mno345pqr678""",manual,.*(?i:api[_.-]?key)
secrets.generic.api-key.string.string,string,generic,Generic Secret,WARNING,HIGH,regex,"api_key = ""abc123def456ghi789jkl012mno345pqr678""",manual,"(?<PROPERTY>(?i)(api[_\.-]?key)(?:[0-9a-z\-_\t\.]{0,20}))(?:[\s|']|[\s|""]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=|,|\()(?:'|\""|[ ]|=|\x60){0,5}(?<STRING>[a-zA-Z0-9_.+\!\/~$-]([a-zA-Z0-9_.+\!\/=~$-]|\\(?![ntr\""])){14,150}[a-zA-Z0-9_.+\!\/=~$-])"
secrets.generic.api-key.xml-dict.xml-dict,xml-dict,generic,Generic Secret,WARNING,HIGH,xml,<key>api_key</key><string>abc123def456ghi789jkl012mno345pqr678</string>,manual,.*(?i:api[_.-]?key)
secrets.generic.api-key.xml-string.xml-string,xml-string,generic,Generic Secret,WARNING,HIGH,xml,"<add key=""api_key"" value=""abc123def456ghi789jkl012mno345pqr678"" />",manual,(?i:api[_.-]?key)
secrets.generic.api-key.yaml-string.yaml-string,yaml-string,generic,Generic Secret,WARNING,HIGH,yaml,api_key: abc123def456ghi789jkl012mno345pqr678,manual,(?i:api[_.-]?key)
secrets.generic.client-key-and-secret.yaml-string.yaml-string,yaml-string,generic,Generic Secret,ERROR,HIGH,yaml,"client_id: abc123
client_secret: XyZ987AbC654DeF321GhI098JkL765MnO432PqR109",manual,(?i:client[_-]?(id|secret))
secrets.generic.password.xml-password.xml-password,xml-password,generic,Generic Secret,WARNING,HIGH,xml,<password>P@ssw0rd123!</password>,manual,(?i:password|pwd|passwd)
secrets.misc.generic-config-password.generic-config-password,generic-config-password,misc,Configuration Password,WARNING,HIGH,generic,"db.password = ""P@ssw0rd123!""",manual,
secrets.misc.generic_amqp_string.generic_amqp_string,generic_amqp_string,misc,Connection URI,WARNING,HIGH,regex,amqp://rabbituser:RabbitPass@rabbit.internal:5672/vhost,manual,"\bamqps?://(?<USERNAME>[\S]{3,50}):(?<REGEX>([\S]{3,50}))@[-.%\w\/:]+\b"
secrets.misc.generic_basic_auth_header.generic_basic_auth_header,generic_basic_auth_header,misc,Authorization Header,WARNING,LOW,regex,Basic kfIourfoqjr1Ke4QA==,regex,"\bBasic (?<REGEX>[A-Za-z0-9]{12,}(?:={1,2})?)"
secrets.misc.generic_ftp_string.generic_ftp_string,generic_ftp_string,misc,Connection URI,WARNING,HIGH,regex,ftp://deploy:FtpPass99@files.internal:21,manual,"\bs?ftp://(?<USERNAME>[\S]{3,50}):(?<REGEX>([\S]{3,50}))@[-.%\w\/:]+\b"
secrets.misc.generic_jwt.generic_jwt,generic_jwt,misc,JWT,WARNING,MEDIUM,regex,eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c,manual,"(?<REGEX>\b(ey[A-Za-z0-9]{17,}\.ey[A-Za-z0-9\/\\_-]{17,}\.(?:[A-Za-z0-9\/\\_-]{10,}={0,2})?))(?:['|\""|\n|\r|\s|\x60|;]|$)"
secrets.misc.generic_mongodb_string.generic_mongodb_string,generic_mongodb_string,misc,Connection URI,WARNING,HIGH,regex,mongodb://appuser:LeakedPw2024@mongo.internal:27017/orders,manual,"\b(mongodb(\+srv)?://(?<USERNAME>[\S]{3,50}):(?<REGEX>([\S]{3,50}))@[-.%\w\/:]+)\b"
secrets.misc.generic_mssql_string.generic_mssql_string,generic_mssql_string,misc,Connection URI,WARNING,HIGH,regex,sqlserver://sa:S3cretPass@sql.internal:1433/master,manual,"\bmssql://(?<USERNAME>[\S]{3,50}):(?<REGEX>([\S]{3,50}))@[-.%\w\/:]+\b"
secrets.misc.generic_mysql_string.generic_mysql_string,generic_mysql_string,misc,Connection URI,WARNING,HIGH,regex,mysql://root:P@ssw0rd123@10.0.0.5:3306/appdb,manual,"\bmysql://(?<USERNAME>[\S]{3,50}):(?<REGEX>([\S]{3,50}))@[-.%\w\/:]+\b"
secrets.misc.generic_postgres_string.generic_postgres_string,generic_postgres_string,misc,Connection URI,WARNING,HIGH,regex,postgres://admin:hunter2@db.internal:5432/prod,manual,"\bpostgres(ql)?://(?<USERNAME>[\S]{3,50}):(?<REGEX>([\S]{3,50}))@[-.%\w\/:]+\b"
secrets.misc.generic_private_key_pgp.generic_private_key_pgp,generic_private_key_pgp,misc,Private Key,ERROR,HIGH,regex,"-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v2

lQOYBGX000BCADeXampleFakePgpKeyBlockContentGoesHereJustEnoughToMatchRegex
=AbCd
-----END PGP PRIVATE KEY BLOCK-----",manual,(?i)-----\s*?BEGIN PGP PRIVATE KEY( BLOCK)?-----[\s\S]*?(?:Version:.*?\n)?(?:Comment:.*?\n)?(?<REGEX>(?:(?!Version:|Comment:)[\s\S])*?)-----END PGP PRIVATE KEY BLOCK-----
secrets.misc.generic_redis_string.generic_redis_string,generic_redis_string,misc,Connection URI,WARNING,HIGH,regex,redis://:RedisTopSecret@cache.internal:6379/0,manual,"\bredis://(?<USERNAME>[\S]{3,50}):(?<REGEX>([\S]{3,50}))@[-.%\w\/:]+\b"
secrets.misc.generic_solr_string.generic_solr_string,generic_solr_string,misc,Connection URI,WARNING,HIGH,regex,http://solradmin:SolrPass@solr.internal:8983/solr,manual,"\bsolr://(?<USERNAME>[\S]{3,50}):(?<REGEX>([\S]{3,50}))@[-.%\w\/:]+\b"
secrets.misc.generic_uri_string.generic_uri_string,generic_uri_string,misc,Connection URI,WARNING,HIGH,regex,https://serviceuser:HttpPass23@api.internal/v1/status,manual,"\b(?:https?:)?\/\/(?<TUPLE>(?<USERNAME>[\S]{3,50}):(?<REGEX>([\S]){3,50}))@(?<URL>[-.%\w\/:]+)\b"
secrets.misc.putty_private_key.putty_private_key,putty_private_key,misc,Private Key,ERROR,HIGH,regex,"PuTTY-User-Key-File-2: ssh-rsa
Encryption: none
Private-Lines: 4
AAAAgQCxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx==",manual,"(Private-Lines\:[ ][0-9]{1,4})[\r\n]+(?<REGEX>[a-zA-Z0-9\/\\_+\-\r\n]{40,}={0,2})"
secrets.misc.rails_secret_key_base.rails_secret_key_base,rails_secret_key_base,misc,Private Key,ERROR,HIGH,yaml,secret_key_base,regex,secret_key_base
secrets.semantic.bash.curl-h.curl-h,curl-h,semantic,Connection URI,WARNING,HIGH,bash,"curl -H ""Authorization: Bearer sk-live-51H8xYzAbCdEfGhIjKlMnOpQrStUvWxYz0123456789"" https://api.example.com/v1/data",manual,curl
secrets.semantic.bash.curl-u-api-key.curl-u-api-key,curl-u-api-key,semantic,Connection URI,WARNING,HIGH,bash,"curl -u ""api_key:sk_live_abc123def456ghi789jkl012mno345pqr678"" https://api.stripe.com/v1/charges",manual,curl
secrets.semantic.bash.curl-u.curl-u,curl-u,semantic,Connection URI,WARNING,HIGH,bash,curl -u admin:P@ssw0rd123! https://api.example.com/v1/private,manual,curl
secrets.semantic.golang.apache.detect_hardcoded_solr_empty_password.solr_empty,solr_empty,semantic,Connection URI,INFO,HIGH,go,"dsn := ""http://solradmin:@solr.internal:8983/solr""",template,(?i)solr
secrets.semantic.golang.apache.detect_hardcoded_solr_password.solr,solr,semantic,Connection URI,WARNING,HIGH,go,"dsn := ""http://solradmin:SolrPass!@solr.internal:8983/solr""",template,(?i)solr
secrets.semantic.golang.cryptography.crypto-aes-static-key.aes-static-key,aes-static-key,semantic,Static Encryption Key,ERROR,HIGH,go,"aesStaticKey := []byte(""0123456789abcdef0123456789abcdef"")",manual,Cipher_AES
secrets.semantic.golang.cryptography.crypto-chacha-static-key.chacha-static-key,chacha-static-key,semantic,Static Encryption Key,ERROR,HIGH,go,"chachaStaticKey := []byte(""abcdefghijklmnopqrstuvwxyz012345"")",manual,NewX?
secrets.semantic.golang.database.detect_hardcoded_mongo_empty_password.mongo_empty,mongo_empty,semantic,Connection URI,INFO,HIGH,go,"dsn := ""mongodb://appuser:@mongo.internal:27017/orders""",template,(?i)mongodb(\+srv)?
secrets.semantic.golang.database.detect_hardcoded_mongo_password.mongo,mongo,semantic,Connection URI,WARNING,HIGH,go,"dsn := ""mongodb://appuser:LeakedPw2024@mongo.internal:27017/orders""",template,(?i)mongodb(\+srv)?
secrets.semantic.golang.database.detect_hardcoded_mssql_password.mssql,mssql,semantic,Connection URI,WARNING,HIGH,go,"dsn := ""sqlserver://sa:S3cretPass!@sql.internal:1433/master""",template,(?i)mssql
secrets.semantic.golang.database.detect_hardcoded_mysql_password.mysql,mysql,semantic,Connection URI,WARNING,HIGH,go,"dsn := ""mysql://root:P@ssw0rd123!@10.0.0.5:3306/appdb""",template,(?i)mysql
secrets.semantic.golang.database.detect_hardcoded_postgres_empty_password.postgres_empty,postgres_empty,semantic,Connection URI,INFO,HIGH,go,"dsn := ""postgres://admin:@db.internal:5432/prod""",template,(?i)postgres
secrets.semantic.golang.database.detect_hardcoded_postgres_password.postgres,postgres,semantic,Connection URI,WARNING,HIGH,go,"dsn := ""postgres://admin:hunter2@db.internal:5432/prod""",template,(?i)postgres
secrets.semantic.golang.fileshare.detect_hardcoded_ftp_empty_password.ftp_empty,ftp_empty,semantic,Connection URI,INFO,HIGH,go,"dsn := ""ftp://deploy:@files.internal:21""",template,(?i)s?ftp
secrets.semantic.golang.fileshare.detect_hardcoded_ftp_password.ftp,ftp,semantic,Connection URI,WARNING,HIGH,go,"dsn := ""ftp://deploy:FtpPass99@files.internal:21""",template,(?i)s?ftp
secrets.semantic.golang.fileshare.smb-hardcoded-password.smb-hardcoded-password,smb-hardcoded-password,semantic,Static Fileshare Credential,WARNING,HIGH,go,"smbPassword := ""SmbP@ss2024""",manual,
secrets.semantic.golang.http.auth-header-hardcoded-token.auth-header,auth-header,semantic,Authorization Header,WARNING,HIGH,go,"req.Header.Set(""Authorization"", ""Bearer sk-live-51H8xYzAbCdEfGh0123456789"")",manual,
secrets.semantic.golang.http.basicauth-hardcoded-password.basicauth,basicauth,semantic,Authorization Header,WARNING,HIGH,go,"req.SetBasicAuth(""svcuser"", ""BasicAuthP@ss!"")",manual,
secrets.semantic.golang.http.detect_hardcoded_http_empty_password.http_empty,http_empty,semantic,Connection URI,INFO,HIGH,go,"dsn := ""http://serviceuser:@api.internal/v1/status""",template,(?i)https?
secrets.semantic.golang.http.detect_hardcoded_http_password.http,http,semantic,Connection URI,WARNING,HIGH,go,"dsn := ""http://serviceuser:HttpPass!23@api.internal/v1/status""",template,(?i)https?
secrets.semantic.golang.microsoft.ldap-hardcoded-password.ldap-static-password,ldap-static-password,semantic,Static LDAP Credential,WARNING,HIGH,go,"ldapBindPw := ""LdapBindP@ss!""",manual,
secrets.semantic.java.http.java-auth-header-format.java-auth-header-format,java-auth-header-format,semantic,Authorization Header,WARNING,HIGH,java,"String auth = String.format(""Basic %s"", ""YWRtaW46U3VwZXJTZWNyZXQ="");",manual,Http(Get|Post|Patch|Put|Delete)
secrets.semantic.java.http.java-auth-header.java-auth-header,java-auth-header,semantic,Authorization Header,WARNING,HIGH,java,"req.setHeader(""Authorization"", ""Bearer sk-live-51H8xYzAbCdEfGh0123456789"");",manual,Http(Get|Post|Patch|Put|Delete)
secrets.semantic.java.string_format.detect_hardcoded_amqp_password.amqp,amqp,semantic,Connection URI,WARNING,HIGH,java,"String dsn = ""amqp://rabbituser:RabbitPass!@rabbit.internal:5672/vhost"";",template,(?i)amqps?
secrets.semantic.java.string_format.detect_hardcoded_ftp_empty_password.ftp_empty,ftp_empty,semantic,Connection URI,INFO,HIGH,java,"String dsn = ""ftp://deploy:@files.internal:21"";",template,(?i)s?ftp
secrets.semantic.java.string_format.detect_hardcoded_ftp_password.ftp,ftp,semantic,Connection URI,WARNING,HIGH,java,"String dsn = ""ftp://deploy:FtpPass99@files.internal:21"";",template,(?i)s?ftp
secrets.semantic.java.string_format.detect_hardcoded_http_empty_password.http_empty,http_empty,semantic,Connection URI,INFO,HIGH,java,"String dsn = ""http://serviceuser:@api.internal/v1/status"";",template,(?i)https?
secrets.semantic.java.string_format.detect_hardcoded_http_password.http,http,semantic,Connection URI,WARNING,HIGH,java,"String dsn = ""http://serviceuser:HttpPass!23@api.internal/v1/status"";",template,(?i)https?
secrets.semantic.java.string_format.detect_hardcoded_mongo_empty_password.mongo_empty,mongo_empty,semantic,Connection URI,INFO,HIGH,java,"String dsn = ""mongodb://appuser:@mongo.internal:27017/orders"";",template,(?i)mongodb(\+srv)?
secrets.semantic.java.string_format.detect_hardcoded_mongo_password.mongo,mongo,semantic,Connection URI,WARNING,HIGH,java,"String dsn = ""mongodb://appuser:LeakedPw2024@mongo.internal:27017/orders"";",template,(?i)mongodb(\+srv)?
secrets.semantic.java.string_format.detect_hardcoded_mssql_password.mssql,mssql,semantic,Connection URI,WARNING,HIGH,java,"String dsn = ""sqlserver://sa:S3cretPass!@sql.internal:1433/master"";",template,(?i)mssql
secrets.semantic.java.string_format.detect_hardcoded_mysql_password.mysql,mysql,semantic,Connection URI,WARNING,HIGH,java,"String dsn = ""mysql://root:P@ssw0rd123!@10.0.0.5:3306/appdb"";",template,(?i)mysql
secrets.semantic.java.string_format.detect_hardcoded_postgres_empty_password.postgres_empty,postgres_empty,semantic,Connection URI,INFO,HIGH,java,"String dsn = ""postgres://admin:@db.internal:5432/prod"";",template,(?i)postgres
secrets.semantic.java.string_format.detect_hardcoded_postgres_password.postgres,postgres,semantic,Connection URI,WARNING,HIGH,java,"String dsn = ""postgres://admin:hunter2@db.internal:5432/prod"";",template,(?i)postgres
secrets.semantic.java.string_format.detect_hardcoded_solr_empty_password.solr_empty,solr_empty,semantic,Connection URI,INFO,HIGH,java,"String dsn = ""http://solradmin:@solr.internal:8983/solr"";",template,(?i)solr
secrets.semantic.java.string_format.detect_hardcoded_solr_password.solr,solr,semantic,Connection URI,WARNING,HIGH,java,"String dsn = ""http://solradmin:SolrPass!@solr.internal:8983/solr"";",template,(?i)solr
secrets.semantic.javascript.core.url.password,password,semantic,Connection URI,WARNING,HIGH,javascript;typescript,"const url = new URL(""https://user:P@ssw0rd!@api.example.com"");",manual,
secrets.semantic.javascript.template_literal_string.detect_hardcoded_amqp_password.amqp,amqp,semantic,Connection URI,WARNING,HIGH,javascript;typescript,const dsn = `amqp://rabbituser:RabbitPass!@rabbit.internal:5672/vhost`;,template,(?i)amqps?
secrets.semantic.javascript.template_literal_string.detect_hardcoded_apikey.js-api-key,js-api-key,semantic,Generic Secret,WARNING,HIGH,javascript;typescript,const apiKey = `sk-live-51H8xYzAbCdEfGhIjKlMnOpQrStUvWxYz0123456789`;,manual,(?i)api[_-]?key
secrets.semantic.javascript.template_literal_string.detect_hardcoded_ftp_empty_password.ftp_empty,ftp_empty,semantic,Connection URI,INFO,HIGH,javascript;typescript,const dsn = `ftp://deploy:@files.internal:21`;,template,(?i)s?ftp
secrets.semantic.javascript.template_literal_string.detect_hardcoded_ftp_password.ftp,ftp,semantic,Connection URI,WARNING,HIGH,javascript;typescript,const dsn = `ftp://deploy:FtpPass99@files.internal:21`;,template,(?i)s?ftp
secrets.semantic.javascript.template_literal_string.detect_hardcoded_http_empty_password.http_empty,http_empty,semantic,Connection URI,INFO,HIGH,javascript;typescript,const dsn = `http://serviceuser:@api.internal/v1/status`;,template,(?i)https?
secrets.semantic.javascript.template_literal_string.detect_hardcoded_http_password.http,http,semantic,Connection URI,WARNING,HIGH,javascript;typescript,const dsn = `http://serviceuser:HttpPass!23@api.internal/v1/status`;,template,(?i)https?
secrets.semantic.javascript.template_literal_string.detect_hardcoded_mongo_empty_password.mongo_empty,mongo_empty,semantic,Connection URI,INFO,HIGH,javascript;typescript,const dsn = `mongodb://appuser:@mongo.internal:27017/orders`;,template,(?i)mongodb(\+srv)?
secrets.semantic.javascript.template_literal_string.detect_hardcoded_mongo_password.mongo,mongo,semantic,Connection URI,WARNING,HIGH,javascript;typescript,const dsn = `mongodb://appuser:LeakedPw2024@mongo.internal:27017/orders`;,template,(?i)mongodb(\+srv)?
secrets.semantic.javascript.template_literal_string.detect_hardcoded_mssql_password.mssql,mssql,semantic,Connection URI,WARNING,HIGH,javascript;typescript,const dsn = `sqlserver://sa:S3cretPass!@sql.internal:1433/master`;,template,(?i)mssql
secrets.semantic.javascript.template_literal_string.detect_hardcoded_mysql_password.mysql,mysql,semantic,Connection URI,WARNING,HIGH,javascript;typescript,const dsn = `mysql://root:P@ssw0rd123!@10.0.0.5:3306/appdb`;,template,(?i)mysql
secrets.semantic.javascript.template_literal_string.detect_hardcoded_postgres_empty_password.postgres_empty,postgres_empty,semantic,Connection URI,INFO,HIGH,javascript;typescript,const dsn = `postgres://admin:@db.internal:5432/prod`;,template,(?i)postgres
secrets.semantic.javascript.template_literal_string.detect_hardcoded_postgres_password.postgres,postgres,semantic,Connection URI,WARNING,HIGH,javascript;typescript,const dsn = `postgres://admin:hunter2@db.internal:5432/prod`;,template,(?i)postgres
secrets.semantic.javascript.template_literal_string.detect_hardcoded_solr_empty_password.solr_empty,solr_empty,semantic,Connection URI,INFO,HIGH,javascript;typescript,const dsn = `http://solradmin:@solr.internal:8983/solr`;,template,(?i)solr
secrets.semantic.javascript.template_literal_string.detect_hardcoded_solr_password.solr,solr,semantic,Connection URI,WARNING,HIGH,javascript;typescript,const dsn = `http://solradmin:SolrPass!@solr.internal:8983/solr`;,template,(?i)solr
secrets.semantic.json.gcp_oauth.gcp_oauth,gcp_oauth,semantic,Google Cloud,ERROR,HIGH,json,auth_provider_x509_cert_url,regex,auth_provider_x509_cert_url
secrets.semantic.python.formatted_string_literal.detect_hardcoded_amqp_password.amqp,amqp,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""amqp://rabbituser:RabbitPass!@rabbit.internal:5672/vhost""",template,(?i)amqps?
secrets.semantic.python.formatted_string_literal.detect_hardcoded_ftp_empty_password.ftp_empty,ftp_empty,semantic,Connection URI,INFO,HIGH,python,"dsn = f""ftp://deploy:@files.internal:21""",template,(?i)s?ftp
secrets.semantic.python.formatted_string_literal.detect_hardcoded_ftp_password.ftp,ftp,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""ftp://deploy:FtpPass99@files.internal:21""",template,(?i)s?ftp
secrets.semantic.python.formatted_string_literal.detect_hardcoded_http_empty_password.http_empty,http_empty,semantic,Connection URI,INFO,HIGH,python,"dsn = f""http://serviceuser:@api.internal/v1/status""",template,(?i)https?
secrets.semantic.python.formatted_string_literal.detect_hardcoded_http_password.http,http,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""http://serviceuser:HttpPass!23@api.internal/v1/status""",template,(?i)https?
secrets.semantic.python.formatted_string_literal.detect_hardcoded_mongo_empty_password.mongo_empty,mongo_empty,semantic,Connection URI,INFO,HIGH,python,"dsn = f""mongodb://appuser:@mongo.internal:27017/orders""",template,(?i)mongodb(\+srv)?
secrets.semantic.python.formatted_string_literal.detect_hardcoded_mongo_password.mongo,mongo,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""mongodb://appuser:LeakedPw2024@mongo.internal:27017/orders""",template,(?i)mongodb(\+srv)?
secrets.semantic.python.formatted_string_literal.detect_hardcoded_mssql_password.mssql,mssql,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""sqlserver://sa:S3cretPass!@sql.internal:1433/master""",template,(?i)mssql
secrets.semantic.python.formatted_string_literal.detect_hardcoded_mysql_password.mysql,mysql,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""mysql://root:P@ssw0rd123!@10.0.0.5:3306/appdb""",template,(?i)mysql
secrets.semantic.python.formatted_string_literal.detect_hardcoded_postgres_empty_password.postgres_empty,postgres_empty,semantic,Connection URI,INFO,HIGH,python,"dsn = f""postgres://admin:@db.internal:5432/prod""",template,(?i)postgres
secrets.semantic.python.formatted_string_literal.detect_hardcoded_postgres_password.postgres,postgres,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""postgres://admin:hunter2@db.internal:5432/prod""",template,(?i)postgres
secrets.semantic.python.formatted_string_literal.detect_hardcoded_solr_empty_password.solr_empty,solr_empty,semantic,Connection URI,INFO,HIGH,python,"dsn = f""http://solradmin:@solr.internal:8983/solr""",template,(?i)solr
secrets.semantic.python.formatted_string_literal.detect_hardcoded_solr_password.solr,solr,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""http://solradmin:SolrPass!@solr.internal:8983/solr""",template,(?i)solr
secrets.semantic.python.http.py-auth-header-aiohttp.py-auth-header-aiohttp,py-auth-header-aiohttp,semantic,Authorization Header,WARNING,HIGH,python,"auth = aiohttp.BasicAuth(login=""admin"", password=""P@ssw0rd!"")",manual,(get|post|put|patch|delete|head|options)
secrets.semantic.python.http.py-auth-header-httpx.py-auth-header-httpx,py-auth-header-httpx,semantic,Authorization Header,WARNING,HIGH,python,"httpx.put(""https://api.example.com/v1"", headers={""Authorization"": ""Bearer sk-live-abc123def456ghi789jkl012mno345""})",manual,(get|post|put|patch|delete|head|options)
secrets.semantic.python.http.py-auth-header-requests.py-auth-header-requests,py-auth-header-requests,semantic,Authorization Header,WARNING,HIGH,python,"requests.get(""https://api.example.com/v1"", headers={""Authorization"": ""Bearer sk-live-abc123def456ghi789jkl012mno345""})",manual,(get|post|put|patch|delete|head|options)
secrets.semantic.python.jenkins.jenkinsapi.hardcoded-password,hardcoded-password,semantic,Jenkins,WARNING,HIGH,python,"j = Jenkins(""http://jenkins.internal"", username=""admin"", password=""J3nk1nsP@ss!"")",manual,
secrets.semantic.python.jenkins.python-jenkins.hardcoded-password,hardcoded-password,semantic,Jenkins,WARNING,HIGH,python,"j = jenkins.Jenkins(""http://jenkins.internal"", username=""admin"", password=""J3nk1nsP@ss!"")",manual,
secrets.semantic.python.string_format_literal.detect_hardcoded_amqp_password.amqp,amqp,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""amqp://rabbituser:RabbitPass!@rabbit.internal:5672/vhost""",template,(?i)amqps?
secrets.semantic.python.string_format_literal.detect_hardcoded_ftp_password.ftp,ftp,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""ftp://deploy:FtpPass99@files.internal:21""",template,(?i)s?ftp
secrets.semantic.python.string_format_literal.detect_hardcoded_http_password.http,http,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""http://serviceuser:HttpPass!23@api.internal/v1/status""",template,(?i)https?
secrets.semantic.python.string_format_literal.detect_hardcoded_mongo_password.mongo,mongo,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""mongodb://appuser:LeakedPw2024@mongo.internal:27017/orders""",template,(?i)mongodb(\+srv)?
secrets.semantic.python.string_format_literal.detect_hardcoded_mssql_password.mssql,mssql,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""sqlserver://sa:S3cretPass!@sql.internal:1433/master""",template,(?i)mssql
secrets.semantic.python.string_format_literal.detect_hardcoded_mysql_password.mysql,mysql,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""mysql://root:P@ssw0rd123!@10.0.0.5:3306/appdb""",template,(?i)mysql
secrets.semantic.python.string_format_literal.detect_hardcoded_postgres_password.postgres,postgres,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""postgres://admin:hunter2@db.internal:5432/prod""",template,(?i)postgres
secrets.semantic.python.string_format_literal.detect_hardcoded_solr_password.solr,solr,semantic,Connection URI,WARNING,HIGH,python,"dsn = f""http://solradmin:SolrPass!@solr.internal:8983/solr""",template,(?i)solr
secrets.semantic.terraform.administrator_login_password.administrator_login_password,administrator_login_password,semantic,Configuration Password,ERROR,HIGH,terraform,"administrator_login_password = ""P@ssw0rd123!""",manual,
secrets.semantic.terraform.database_password.database_password,database_password,semantic,Configuration Password,WARNING,HIGH,terraform,"password = ""DbP@ss2024!""",manual,
secrets.semantic.terraform.hardcoded-variable.hardcoded-variable,hardcoded-variable,semantic,Configuration Password,WARNING,HIGH,terraform,"variable ""db_password"" { default = ""SuperSecretP@ss2024!"" }",manual,(?i).*(secret|token|api[_.-]?key|credential|auth|pass(word|wd|phrase)|pwd)
secrets.semantic.terraform.provider_password.provider_password,provider_password,semantic,Configuration Password,WARNING,HIGH,terraform,"provider ""postgresql"" { password = ""PgP@ss2024!"" }",manual,
secrets.semantic.xml.asp.machinekey.machineKey,machineKey,semantic,Private Key,ERROR,HIGH,generic,"<machineKey validationKey=""A1B2C3D4E5F60718293A4B5C6D7E8F901A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D"" decryptionKey=""0011223344556677"" />",manual,
secrets.services.africastalking.africastalking,africastalking,services,AfricasTalking,CRITICAL,MEDIUM,regex,atsk_42761a9d6c46e0fc50591bb0476a75f4db88f15b035a604f28cd69d0fbd6f1f78cb883a3,regex,(?<REGEX>atsk_[a-f0-9]{72})
secrets.services.aikido-oauth.aikido-oauth,aikido-oauth,services,Aikido,WARNING,MEDIUM,regex,AIK_SECRET_Wohzm78dOOqKbwEYmDRRXkk9Xp6zxD6R2ArNlvNLI22ajzylcwBFyrKMQcp3HwC0,regex,"(?<SECRET>AIK_SECRET_[A-Za-z0-9]{64,65})"
secrets.services.aiproxy.aiproxy,aiproxy,services,AIProxy,INFO,MEDIUM,regex,v2|33f326a4|YXL3Og_5FaU7xLm3,regex,(?<REGEX>\b(v2\|[a-f0-9]{8}\|[A-Za-z0-9-_]{16})\b)
secrets.services.airtable-oauth.airtable-oauth,airtable-oauth,services,Airtable,WARNING,MEDIUM,regex,"clientsecret

d4a9a65fc3a814bc6bf4de41b72d3241575b019c8d5a1568c48ba822107d11f9",regex,"(?i:client[-_]?secret)(?:\R|.){0,40}(?<SECRET>\b([a-f0-9]{64})\b)"
secrets.services.airtable-token.airtable-token,airtable-token,services,Airtable,WARNING,MEDIUM,regex,J4nZM5MvNkTOElRVq.v3.eyJr_yTEH.463a61be7946420a326c6f7ee81eac925b3555a7a0d493725c023291fd3a30c5,regex,(?<REGEX>\b[A-Za-z0-9]{17}\.v[0-9]{1}\.eyJ[A-Za-z0-9-_]+\.[a-f0-9]{64}\b)
secrets.services.akamai.akamai,akamai,services,Akamai,ERROR,MEDIUM,regex,secretS4uvlw/88ALh5O/Rssxgpi6rUmWCiF4ku8i9OIHQxb1d,regex,"(?i:secret)(?:\R|.){0,40}(?<CLIENT_SECRET>\b([0-9A-Za-z/+=]{44}))"
secrets.services.alchemy.alchemy,alchemy,services,Alchemy,ERROR,MEDIUM,regex,alcht_:]]]]]]]]]]]]]]]]]]]]]]]]]]]]]],regex,(?<KEY>alcht_[[:alnum:]]{30})
secrets.services.alibaba-cloud.alibaba-cloud,alibaba-cloud,services,Alibaba,CRITICAL,MEDIUM,regex,"alibabaM
F
G9NifuXNha4uXjdpl4Z1cByU3ePKl2",regex,"(?i:alibaba)(?:\R|.){0,40}(?<TOKEN>\b([a-zA-Z0-9]{30})\b)"
secrets.services.amp.amp,amp,services,Amp,ERROR,MEDIUM,regex,sgamp_user_OMX6LSO4B8RUKIWH1GG2FUIALN_71c795bf531680ea728e8de04c3c35d7ff8048715d732d422fb536af05cc6bdd,regex,(?<REGEX>sgamp_user_[0-9A-Z]{26}_[0-9a-f]{64})
secrets.services.amplitude-v2.amplitude-v2,amplitude-v2,services,Amplitude,ERROR,MEDIUM,regex,"amplitude

6527a66fa791c4d2004fea343b5c6657",regex,"(?i:amplitude|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.anthropic-admin.anthropic-admin,anthropic-admin,services,Anthropic,ERROR,MEDIUM,regex,sk-ant-admin01-mLR9p4wfZ7yVIYDpy6dVwltFmOIgAxwHQrwIh5iFhmHqN0F0HLqjub8va6TlqplenDPw2oXu9YroJBXOPjJ0A,regex,"(?<REGEX>sk-ant-admin01-[A-Za-z0-9_-]{84,}A)"
secrets.services.anthropic.anthropic,anthropic,services,Anthropic,ERROR,MEDIUM,regex,sk-ant-api03-ÆeõËÍµÌíkÙÄàÞohñOæçÍØgÞ²µ3Ï0³¾ÇfäéûóýÄîénFìïfäbê6OoçBÆø¾ØèÚÈÀÒHIÌYZdâa_þÏûLDZÆºuüúBaÜãoxlÍÝdÂAA,regex,(?<REGEX>(sk-ant-api03-[\w\-]{93}AA))
secrets.services.apify-proxy.apify-proxy,apify-proxy,services,Apify,WARNING,MEDIUM,regex,apify_proxy_E-5uXoouegKkYGE4uKAyd59LRB6nTiVjkuyY,regex,(?<REGEX>(apify_proxy_[a-zA-Z-0-9]{36}))
secrets.services.asana_pat.asana_pat,asana_pat,services,Asana,ERROR,MEDIUM,regex,2/1015633732936591/2466697467360700:472f823df7569bb7f4bbba4106dc3b64,regex,(?<REGEX>\b(2\/[0-9]{16}\/[0-9]{16}:[a-f0-9]{32}|1\/[0-9]{16}:[a-f0-9]{32})\b)
secrets.services.asi1.asi1,asi1,services,Asi1,WARNING,MEDIUM,regex,sk_5237a7a0179b561512d5ca29ad7db47d70d80408c57783d3e654737bb93f3495,regex,(?<REGEX>\bsk_[a-f0-9]{64}\b)
secrets.services.atlassian-org.atlassian-org,atlassian-org,services,Atlassian,CRITICAL,MEDIUM,regex,ATCTT3xFfGOCwlKSQ6=VWW2CtOn8hWhDH5j-mDRwD=Txt+T1Qdsb6iYf0oYsdL-S_QwP=E9lFdIv5nKcJq+9OJwvAj3clxFMTefoVRs+psw5A9ig6uL2roiOPrimpE6wJ1pIohNaG+gX4o6dR877gO8ZM_Lv5blu-OCWNMe1vOYsbmhgLGmLNkE=dVGJslcG,regex,(?<REGEX>ATCTT3xFfG[A-Za-z0-9+\/=_-]{173}=[A-Za-z0-9]{8})
secrets.services.aws_asia.aws-asia,aws-asia,services,AWS,CRITICAL,MEDIUM,regex,ASIAFTVN6MMAKTMDNO5T,regex,(?<KEY>\b(ASIA[0-9A-Z]{16})\b)
secrets.services.aws_oauth.aws-oauth,aws-oauth,services,AWS,CRITICAL,HIGH,regex,"clientsecret


eaf0af5543b7d95f5cfbce26f5921add51d6016b2c50464183d0396159e28764",regex,"(?i:(?:client|amazon)[-_]?secret)(?:\R|.){0,40}(?<SECRET>\b[a-f0-9]{64}\b)"
secrets.services.aws_secret.aws-secret,aws-secret,services,AWS,CRITICAL,MEDIUM,regex,ABIA2EFN4EPU2UHS6M7X,regex,(?<KEY>\b((AKIA|ABIA|ACCA)[0-9A-Z]{16})\b)
secrets.services.azure-app-configuration.azure-communication-service,azure-communication-service,services,Azure,ERROR,MEDIUM,regex,j3gyWR7zdFV9AGEaJMqKDOD6jBuU8584V7OgDDEZQeQhBlTZzrWmTaYtVDxKMi4i0Jhmbyq33ABumFWcHKRS,regex,(?<REGEX>\b([A-Za-z0-9]{84})\b)
secrets.services.azure-batch.azure-batch,azure-batch,services,Azure,ERROR,MEDIUM,regex,0rZsjbPtyVvtUvcZioGLkzh1N2N3nw=eWrotDwgD5lHO/MdzhfklaPtWMLfNzwNaggeQ1Qn8IcdYWV87X98WRS==,regex,(?<REGEX>\b([A-Za-z0-9+\/=]{86}==))
secrets.services.azure-cognitiveservices.azure-cognitiveservices,azure-cognitiveservices,services,Azure,WARNING,MEDIUM,regex,welq8Xa6H4P21dROxSpfQvbbu5ZqJIUj7NZc0hrgvd5HYcBGNeCFfnxXlCQkYhG1JnyMOsFb4LPnJlFjXVzZ,regex,(?<REGEX>\b([A-Za-z0-9]{84})\b)
secrets.services.azure-communication-service.azure-communication-service,azure-communication-service,services,Azure,ERROR,MEDIUM,regex,ANx6feOQBmuM7FpkVubOZldSY7EujerGdLMYDSlfGBfLSQs8CzHh9zGG7ZhLx2woxVW8my5tmHyibQq0eHm7,regex,(?<REGEX>\b([a-zA-Z0-9]{84})\b)
secrets.services.azure-content-moderator.azure-content-moderator,azure-content-moderator,services,Azure,WARNING,MEDIUM,regex,7ffc49b1597016580895cdaf8c877e38,regex,(?<REGEX>\b([a-f0-9]{32})\b)
secrets.services.azure-custom-vision-prediction.azure-custom-vision-prediction,azure-custom-vision-prediction,services,Azure,WARNING,MEDIUM,regex,oS3SrgyDxuSrGPY792cqH2rsiNFraPhbwphZGhME5TuiakhJsgBYnxsy37lg9eI9DXtqQHUPwzk3debqqFUL,regex,(?<REGEX>\b([A-Za-z0-9]{84})\b)
secrets.services.azure-custom-vision-training.azure-custom-vision-training,azure-custom-vision-training,services,Azure,WARNING,MEDIUM,regex,zq5s1QxHQ0h18eQ5M3g6viuFm67BTV1gBy0QZyvZWf0ixGkNAwuqqSODhUXMrbWOIl753Jkpb88iXYWmDZ3W,regex,(?<REGEX>\b([A-Za-z0-9]{84})\b)
secrets.services.azure-devops-pat.azure-devops-pat,azure-devops-pat,services,Azure,CRITICAL,MEDIUM,regex,"pat
0wz1d25xlgeam7kvt4bmyi8pgptp736zemi4mdisg7riw099d22n",regex,"(?i:token|pat)(?:\R|.){0,40}(?<SECRET>\b[a-z0-9]{52}\b)"
secrets.services.azure-entra-secret.azure-entra-secret,azure-entra-secret,services,Azure,ERROR,MEDIUM,regex,secret3mxKQ29kY99DGEUNpG5JwkHUuFzgczLQyQj4BcAc,regex,"(?i:secret)(?:\R|.){0,40}(?<REGEX>\b([a-zA-Z0-9_\.\-~]{40})\b)"
secrets.services.azure-event-grid.azure-event-grid,azure-event-grid,services,Azure,WARNING,MEDIUM,regex,Uvx49sS57mJfYwzaR6FQn0uAClbvXIju1ipGUmLLiBkaghG6uXOyUPqIrxFO5bBeBWQM7JzuyLTFDNZ9DDIq,regex,(?<REGEX>\b([a-zA-Z0-9]{84})\b)
secrets.services.azure-iot-connection.azure-iot-connection,azure-iot-connection,services,Azure,ERROR,MEDIUM,regex,1S+qRQ0iaom55w73bAvPFYhrilg4RMvy/AeFJYjC5OM=,regex,(?<REGEX>\b([A-Za-z0-9\/+]{43}=))
secrets.services.azure-maps.azure-maps,azure-maps,services,Azure,INFO,MEDIUM,regex,keyb5Bg5NWNbSQLw9plUoCAhSTqyGm2jepiPgsOtNLa8DQk4lAwgzDuWMfXCyZAluNaumXoGeKfjVduFiHnpF69i,regex,"(?i:api|key)(?:\R|.){0,40}(?<REGEX>\b([a-zA-Z0-9]{84})\b)"
secrets.services.azure-oauth.azure-oauth,azure-oauth,services,Azure,CRITICAL,MEDIUM,regex,"client-id
490edce4-f39a-28eb-15b3-8a3923f9de4b",regex,"(?i:client[-_]?id)(?:\R|.){0,40}(?<ID>([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}))"
secrets.services.azure-pubsub.azure-pubsub,azure-pubsub,services,Azure,WARNING,MEDIUM,regex,ZNSy8kINtJLRgHTvqsjssePqLJDIUZYod6OTr2ohWjgqZqmezUpA4Uo9S5rHJ0Q4IwX57RRplqXgMnTZRW5y,regex,(?<REGEX>\b([a-zA-Z0-9]{84})\b)
secrets.services.azure-redis-cache.azure-redis-cache,azure-redis-cache,services,Azure,ERROR,MEDIUM,regex,BDFOS1WUqtEXQTS2JrI7AtkBpesB56J4rdblBmeH1bV,regex,(?<REGEX>\b([A-Za-z0-9\/+]{43})\b)
secrets.services.azure-relay.azure-relay,azure-relay,services,Azure,ERROR,MEDIUM,regex,gIbIFVgXGH4+4wXqTTXReKDsDFqo2RYU0h9h7kFGTQt=,regex,(?<REGEX>\b([A-Za-z0-9\/+]{43}=))
secrets.services.azure-signalr.azure-signalr,azure-signalr,services,Azure,WARNING,MEDIUM,regex,R2zY6eiBZlmkMQlrVNs6p23pLfOs0Z3MhajmDaaDTGhYWquCRZvcuFpJYDO9fmByUiBUuGUH9DFxEbJPYwBL,regex,(?<REGEX>\b([a-zA-Z0-9]{84})\b)
secrets.services.azure-speech.azure-speech,azure-speech,services,Azure,WARNING,MEDIUM,regex,jmvmiKxCcWsVFTtdJtz0WWFs68HIrj6xyteiPChJRq1mNW2DyW1hqw5ENMG0ZBpJs5WpButil3qHYl513ovz,regex,(?<REGEX>\b([A-Za-z0-9]{84})\b)
secrets.services.azure-storage.azure-storage,azure-storage,services,Azure,ERROR,MEDIUM,regex,storage-keyvoj=s0oH1fchHXrLvdG=VlNPpd3dwOMnFMAkQ4ItvKWuZRXV7Xsqlt5O0REPdbqT85kHiwZxz=m/I/dCYKNjnY==,regex,"(?i:(access|account|azure|storage)[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([A-Za-z0-9+\/=]{86}==))"
secrets.services.azure-text-translation.azure-text-translation,azure-text-translation,services,Azure,WARNING,MEDIUM,regex,b8gN95sTmBMEsT5QaJSenZXfH6UYGYUraZa5G5Qok88j7bqwDSw1EqLlxNswxKMMbaICKJLyAMSpK5gfpu3y,regex,(?<REGEX>\b([A-Za-z0-9]{84})\b)
secrets.services.birdeye.birdeye,birdeye,services,Birdeye,WARNING,MEDIUM,regex,birdeye8cb19fcf3e52a7c4397a080860584801,regex,"(?i:birdeye|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.box-oauth.box-oauth,box-oauth,services,Box,WARNING,MEDIUM,regex,"secret

0YeP4YMxpnwwqcVxvzc0aYtizhnlkK8d",regex,"(?i:secret)(?:\R|.){0,10}(?<SECRET>\b([A-Za-z0-9]{32})\b)"
secrets.services.box.box,box,services,Box,WARNING,MEDIUM,regex,"token
bgFFOayQlpEeEr5xXX8lVDddY0Vh2JCxCq",regex,"(?i:token|bearer)(?:\R|.){0,40}(?<REGEX>\b([A-Za-z0-9]{32})\b)"
secrets.services.browserstack.browserstack,browserstack,services,BrowserStack,WARNING,MEDIUM,regex,keyRCfA5dC23pLb5fIY3MRQq,regex,"(?i:token|key)(?:\R|.){0,40}(?<REGEX>\b([A-Za-z0-9]{20})\b)"
secrets.services.buildkite_agent_regisration.buildkite_agent_registration,buildkite_agent_registration,services,Buildkite,WARNING,MEDIUM,regex,bkar_C3t5itX7.GF95klpeYF7JxrTI3vbDRdovpmQhOJzO2wFRyc3xzrMyDUAhnn22jvCvofR0ub5bRHFP5IfK,regex,(?<REGEX>bkar_[A-Za-z0-9]{8}\.[A-Za-z0-9]{72})
secrets.services.buildkite_portal_secret.buildkite_portal_secret,buildkite_portal_secret,services,Buildkite,WARNING,MEDIUM,regex,bkps_2Hh06HHG_b2348eca23a45fcc887ed029241de95225bf2f5a3fe92be144f3eff0e01a,regex,(?<SECRET>bkps_[A-Za-z0-9]{8}_[a-f0-9]{60})
secrets.services.buildkite_portal_token.buildkite_portal_token,buildkite_portal_token,services,Buildkite,WARNING,MEDIUM,regex,bkpat_KAgdnzVZ_c0eb2402d260a91d330f797ad26a4dd8ac8812db,regex,(?<REGEX>bkpat_[A-Za-z0-9]{8}_[a-f0-9]{40})
secrets.services.captaindata.captaindata,captaindata,services,CaptainData,WARNING,MEDIUM,regex,"captaindata
u<
b8b0d27e394191332b687dde38c2d7d1d313ccbc30874b9b85d4b291ef21227e",regex,"(?i:captaindata|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{64})\b)"
secrets.services.cartesia.cartesia,cartesia,services,Cartesia,WARNING,MEDIUM,regex,sk_car_lAi2wQC3k6WSCK2HrWZAGb,regex,(?<REGEX>sk_car_[A-Za-z0-9]{22})
secrets.services.circleci-projecttoken.circleci-projecttoken,circleci-projecttoken,services,CircleCI,CRITICAL,MEDIUM,regex,CCIPRJ_8eEzdI9tqm5vAn8JutSkgJ_3792c43c39b5d9146da9ef99cec86cdd6ccd29a1,regex,(?<REGEX>CCIPRJ_[A-Za-z0-9]{22}_[a-f0-9]{40})
secrets.services.clerk-webhook.clerk-webhook,clerk-webhook,services,Clerk,INFO,MEDIUM,regex,whsec_UOD1usN5ePGHqDk3mMYt1Gn+<1pXcE2p,regex,(?<REGEX>whsec_[A-Za-z0-9+\/-_]{32})
secrets.services.clerk.clerk,clerk,services,Clerk,ERROR,MEDIUM,regex,sk_live_ELGsHgysLfFG8SqEdPEn0fnjmodcsSB5NXBCrtRMUE,regex,(?<REGEX>sk_(test|live)_[A-Za-z0-9]{42})
secrets.services.clipdrop.clipdrop,clipdrop,services,Clipdrop,WARNING,MEDIUM,regex,c58341f5d4c7b05151c93c1385db08f3e1f0497e3aa7441cadecae42ec937a6a76f8b8ceca5b4be9762b2fb55a7b623d,regex,(?<REGEX>\b([a-f0-9]{96})\b)
secrets.services.cloudelements.cloudelements,cloudelements,services,CloudElements,ERROR,MEDIUM,regex,user0Hb7Pu4Im2vDfPRfpPjesTH4AG1A11U27/iDjtHfzKFZ,regex,"(?i:user)(?:\R|.){0,40}(?<USER>\b([a-zA-Z0-9=+\/]{44}))"
secrets.services.cloudflare-r2-token.cloudflare-r2-token,cloudflare-r2-token,services,Cloudflare,ERROR,MEDIUM,regex,"tokenF
2Uol_aCZwIvpWFnjBpoggyt5MTWs5SVwZJKF-RMr",regex,"(?i:token|api[-_]?key)(?:\R|.){0,40}(?<SECRET>\b([A-Za-z0-9-_]{40})\b)"
secrets.services.cloudflare-tunnel.cloudflare-tunnel,cloudflare-tunnel,services,Cloudflare,ERROR,MEDIUM,regex,tokeneyJhIjoix7of2QpR0Ls6yTUGWE66n14NZGqaXuPTnb3viCAPOJP3D9Wfiv3hFAHMYF7iiJD9cPL74IYHkf7oNQX6gyrQnPPhrAieTFSPiKQ3WWjuZI9pi1Dyl6TAKHtA1w9MWL42tAXsj5mtquzVuOhRwaCe0NRrBN7iSfOpxJhiJPwnseA=,regex,"(?i:install|token)(?:\R|.){0,40}(?<REGEX>\b(eyJhIjoi[A-Za-z0-9]{171,}={0,2}))"
secrets.services.cloudflare-turnstile.cloudflare-turnstile,cloudflare-turnstile,services,Cloudflare,ERROR,MEDIUM,regex,0x4AAAAAbo3hQgn_5eWaFBIp7vBrwmPoq1R,regex,(?<REGEX>\b0x4AAAAA[A-Za-z0-9-_]{27}\b)
secrets.services.cloudinary.cloudinary,cloudinary,services,Cloudinary,ERROR,MEDIUM,regex,"secret?6?z
EryyOQZblks3Yaze9C1ua2diYcN",regex,"(?i:secret)(?:\R|.){0,40}(?<SECRET>\b([0-9A-Za-z]{27})\b)"
secrets.services.codacy-project.codacy-project,codacy-project,services,Codacy,ERROR,MEDIUM,regex,"token
H58830777be006b6d51b52537428c84bea",regex,"(?i:token)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.comet.comet,comet,services,Comet,WARNING,MEDIUM,regex,"api_key/]

hfto4Pc6znlaUorUeutY7XXuQ",regex,"(?i:api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([A-Za-z0-9]{25})\b)"
secrets.services.contentful-cda.contentful-cda,contentful-cda,services,Contentful,WARNING,MEDIUM,regex,"bearer>
gX-_iEzo06canZXicp0e57L-7AN2XyBs8HFhwQP6dEb",regex,"(?i:bearer|token|key)(?:\R|.){0,40}(?<REGEX>\b[A-Za-z0-9-_]{43}\b)"
secrets.services.coralogix-personalkey.coralogix-personalkey,coralogix-personalkey,services,Coralogix,ERROR,MEDIUM,regex,cxup_aDKJwxQqccWrKFU9VgyVidsp8MKOqB,regex,(?<REGEX>cxup_[A-Za-z0-9]{30})
secrets.services.coralogix-senddata.coralogix-senddata,coralogix-senddata,services,Coralogix,WARNING,MEDIUM,regex,cxtp_4j1ywY0oTnEvzPDswwhH4vpIuihgfN,regex,(?<REGEX>cxtp_[A-Za-z0-9]{30})
secrets.services.coralogix-teamkey.coralogix-teamkey,coralogix-teamkey,services,Coralogix,ERROR,MEDIUM,regex,cxtp_iaiTYGnq50YzDQxCyixDFu7AIxLE1x,regex,(?<REGEX>cxtp_[A-Za-z0-9]{30})
secrets.services.coveo.coveo,coveo,services,Coveo,WARNING,MEDIUM,regex,xxa5d6ba45-2de4-e811-8114-5695059b37ce,regex,(?<REGEX>\b(xx[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b)
secrets.services.coze-oauth.coze-oauth,coze-oauth,services,Coze,ERROR,MEDIUM,regex,"secret



)DJ75IpUrZhbauBVaFZIWOEJbGci14c4j7wNnVT8y9eS4mgFL",regex,"(?i:secret)(?:\R|.){0,40}(?<SECRET>\b[0-9A-Za-z]{48}\b)"
secrets.services.coze-pat.coze-pat,coze-pat,services,Coze,ERROR,MEDIUM,regex,pat_qFYSsqV1mNv8deIqGNHWMyPLWtiR1tCvjuDzBqYy1E90NFdnbFDh5wVWZ5N5YM5q,regex,(?<REGEX>pat_[0-9A-Za-z]{64})
secrets.services.coze-token.coze-token,coze-token,services,Coze,ERROR,MEDIUM,regex,czu_YssF3RR7XeDI7sbHJLzScnb5bgnk1SOUtk5IsRo8AQY55NSZNP6RBZxOG1h8Iu7fU,regex,(?<REGEX>(cztei|czu)_[0-9A-Za-z]{65})
secrets.services.craftmypdf.craftmypdf,craftmypdf,services,CraftMyPDF,WARNING,MEDIUM,regex,B9nYOTGI8vJDdW0qepLpLaRJ1YZHugJ8kgLINTd7W==,regex,"(?<REGEX>\b[A-Za-z0-9]{41,42}={1,2})"
secrets.services.cratesio.cratesio,cratesio,services,Crates,CRITICAL,MEDIUM,regex,"cratesY
/

cioeZCNvLnmiQhf3vspe8hb8XGEhQOPFa4d",regex,"(?i:crates)(?:\R|.){0,40}(?<REGEX>\bcio([A-Za-z0-9]){32}\b)"
secrets.services.cursor.cursor,cursor,services,Cursor,WARNING,MEDIUM,regex,key_5b605b91d23d91b9f01b319149532360de97f27bf765d455e571bdf3d886d564,regex,(?<REGEX>\bkey_[a-f0-9]{64}\b)
secrets.services.d7networks.d7networks,d7networks,services,D7Networks,WARNING,MEDIUM,regex,eyJamypO3.eyJG.6WM1,regex,(?<REGEX>\beyJ[0-9A-Za-z]+\.eyJ[0-9A-Za-z]+\.[A-Za-z0-9_-]+\b)
secrets.services.databricks-account.databricks-account,databricks-account,services,Databricks,CRITICAL,MEDIUM,regex,eyJCgOgu.eyJG.euBe,regex,(?<SECRET>\beyJ[0-9A-Za-z]+\.eyJ[0-9A-Za-z]+\.[A-Za-z0-9_-]+\b)
secrets.services.databricks-oauth.databricks-oauth,databricks-oauth,services,Databricks,ERROR,MEDIUM,regex,dose841f6acb7d44598c37d96658c824b043,regex,(?<CLIENT_SEC>dose[a-f0-9]{32})
secrets.services.databricks-refresh.databricks-refresh,databricks-refresh,services,Databricks,ERROR,MEDIUM,regex,doau1f7fc5fa20f4e15babad695413ca421c,regex,(?<REFRESH>doau[a-f0-9]{32})
secrets.services.databricks-workspace.databricks-workspace,databricks-workspace,services,Databricks,ERROR,MEDIUM,regex,eyJ6sT0.eyJym.RpRK,regex,(?<SECRET>\beyJ[0-9A-Za-z]+\.eyJ[0-9A-Za-z]+\.[A-Za-z0-9_-]+\b)
secrets.services.deepl.deepl,deepl,services,DeepL,WARNING,MEDIUM,regex,"auth-key
81d642b8-291d-1140-cefc-a3b6fa75db27",regex,"(?i:api[-_]?key|auth[-_]?key)(?:\R|.){0,40}(?<KEY>\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b)"
secrets.services.discord-bot-token.discord-bot-token,discord-bot-token,services,Discord,WARNING,MEDIUM,regex,rCcIy6kIw04Z8kKO0sUihmhd.GBphPQ.AfvLSpT3cfY3LD12yppbROq51D9,regex,"(?<KEY>\b([a-zA-Z0-9]{24}\.[a-zA-Z0-9]{6}\.[A-Za-z0-9_-]{27,38})\b)"
secrets.services.disqus-oauth.disqus-oauth,disqus-oauth,services,Disqus,WARNING,MEDIUM,regex,"apiid@

16oy8OIhbQPCHmf3GajH152Cx4CYGIaaZbDR0CFpsMT4Jtj3p0IQICrtxde2Ac3p",regex,"(?i:client|api[-_]?id|key)(?:\R|.){0,40}(?<KEY>\b([a-zA-Z0-9]{64})\b)"
secrets.services.disqus.disqus,disqus,services,Disqus,WARNING,MEDIUM,regex,"access-tokeng
2a20c2f25df1f048d3736ad6d339d350a",regex,"(?i:access[-_]?token)(?:\R|.){0,40}(?<TOKEN>\b([a-f0-9]{32})\b)"
secrets.services.dotdigital.dotdigital,dotdigital,services,Dotdigital,WARNING,MEDIUM,regex,"password
o-F8`a?Z#2M<z",regex,"(?i:password)(?:\R|.){0,10}(?<PASSWORD>.{8,}\b)"
secrets.services.dropbox.dropbox,dropbox,services,Dropbox,ERROR,MEDIUM,regex,sl.ezYfNI8CrFodnyVN0ApHNcpJTqtb3uF3qOn9A_VM5LEwykeOYnqQHedO4uBsKxpAtks_R_owxjB0H-7jpxvynHcH6xBA9vHDB7w0HvFUH9R1BVjJT8BXVMVLtW6SVzQ9wL,regex,"(?<REGEX>(sl\.[A-Za-z0-9\-\_]{130,140}))"
secrets.services.dropbox_refresh.dropbox_refresh,dropbox_refresh,services,Dropbox,ERROR,MEDIUM,regex,C1KohIbzW1wAAAAAAAAAAm13P9gkUWje8WoW3YdZYQimgKihwZ5CCLLV8KG1kFpX,regex,(?<TOKEN>\b[a-zA-Z0-9]{11}AAAAAAAAAA[a-zA-Z0-9\-\_=]{43}\b)
secrets.services.dynatrace.dynatrace,dynatrace,services,Dynatrace,ERROR,MEDIUM,regex,dt0k64.0UUE5SDWWFHGJWT9R65A3URI.Q7JRSNL27OELUBNPNHLN5SUBY1DJF8EJ5A70SWT67EM03SDIO8BCI9GL08THDNVZ,regex,(?<REGEX>\bdt0[a-zA-Z]{1}[0-9]{2}\.[A-Z0-9]{24}\.[A-Z0-9]{64}\b)
secrets.services.e2b.e2b,e2b,services,E2B,WARNING,MEDIUM,regex,e2b_3fe464a895c6af40b2ec86afd7943a30660d0726,regex,(?<REGEX>e2b_[a-f0-9]{40})
secrets.services.eagleeyenetworks.eagleeyenetworks,eagleeyenetworks,services,Eagleeyenetworks,ERROR,MEDIUM,regex,"password

x
5Xln9g-XvWvWa",regex,"(?i:password)(?:\R|.){0,4}(?<PASSWORD>\b([a-zA-Z0-9!=*@#$&~`%^+-]{10,60})\b)"
secrets.services.eightxeight.eightxeight,eightxeight,services,8x8,WARNING,MEDIUM,regex,"8x8.com
)@
QFLJuJK73pvY5gMGltV1dTocQQ8hSxNLtEJ9rFVF9",regex,"(?i:8x8\.com|bearer)(?:\R|.){0,40}(?<REGEX>\b([a-zA-Z0-9]{41,43})\b)"
secrets.services.elastic.elastic,elastic,services,Elastic,ERROR,MEDIUM,regex,essu_Ay4WsHjsUY3LtHC8TwwfPYcisWYevi1+MYvdSR576W9zytfcEKbODXS/xA6wJPvOpPpFbh4eEt2ZXFY+PhZq5XTh6h,regex,"(?<REGEX>\b(essu_[A-Za-z0-9-_+\/]{90,92}={0,2}))"
secrets.services.enablex.enablex,enablex,services,EnableX,WARNING,MEDIUM,regex,enablexd7QTmJO1cAaIvk86AOH860ZYhLFmMxX2BI90,regex,"(?i:enablex|key)(?:\R|.){0,40}(?<KEY>\b([a-zA-Z0-9]{36})\b)"
secrets.services.firebase-cloud-message.firebase-cloud-message,firebase-cloud-message,services,Google Cloud,WARNING,HIGH,regex,EY83YAsDhsc:APA91bLJM19td1xk2IgvKv_JwSpEYwdjSTHrU0r_7BZUFztv5PnNHunRwkxyk9z9K9e_QN3YeWwzhFfnV3pFt-RmXg5XXl4SItRf6kBKpBGk4zAs03KS0SmwVtHr7ZrFZOUsN2FQOXWm,regex,(?<REGEX>\b[A-Za-z0-9]{11}:APA91b[A-Za-z0-9_-]{134})
secrets.services.freepik.freepik,freepik,services,Freepik,WARNING,MEDIUM,regex,FPSX997af026d224c1c8f51c16a6e792c638,regex,(?<REGEX>FPSX[a-f0-9]{32})
secrets.services.fulcrumapp.fulcrumapp,fulcrumapp,services,Fulcrum,WARNING,MEDIUM,regex,eac37979e03fef5b7e788ba6eb766f40d8300384dda834191be28c889bae5e09583fbdf88ca2abb0,regex,(?<REGEX>\b([a-f0-9]{80})\b)
secrets.services.fxmarket.fxmarket,fxmarket,services,FXMarket,INFO,MEDIUM,regex,"apikey
7YrBs5p_8mGO4xTnnvp7",regex,"(?i:fxmarket|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([0-9Aa-zA-Z\-_]{20})\b)"
secrets.services.gemfury-deploy-token.gemfury-deploy-token,gemfury-deploy-token,services,Gemfury,ERROR,MEDIUM,regex,G4Bv-hek8GpdszTawFHoXjCwU31j31oE,regex,"(?<REGEX>\b(?!sha512-|sha256)[A-Za-z0-9]{4,6}-[A-Za-z0-9]{27}\b)"
secrets.services.gemfury.gemfury,gemfury,services,Gemfury,ERROR,MEDIUM,regex,WSUk9-cHZsnXIQ0WzOnPLfCXV8yxyGweC,regex,"(?<REGEX>\b[A-Za-z0-9]{5,6}-[A-Za-z0-9]{27}\b)"
secrets.services.geoipify.geoipify,geoipify,services,Geoipify,INFO,MEDIUM,regex,at_x0v7wN8Lxw55XV0Vy3IWdZtsPG8va,regex,(?<REGEX>\bat_[a-zA-Z0-9]{29}\b)
secrets.services.github-app-installation.github-app-installation,github-app-installation,services,GitHub,CRITICAL,MEDIUM,regex,ghs_054_eyJWwS.eyJw.tCVv,regex,(?<REGEX>ghs_[0-9]+_eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+)
secrets.services.github_app.github-app,github-app,services,GitHub,CRITICAL,MEDIUM,regex,"-----

BEGIN RSA PRIVATE KEY----- 
----- END RSA PRIVATE KEY
	
-----",regex,(?<SECRET>(?<OUTER>(?i)-----\s*?BEGIN RSA PRIVATE KEY-----)(?<REGEX>[\s\S]*?)-----\s*?END RSA PRIVATE KEY\s*?-----)
secrets.services.github_oauth.github_oauth,github_oauth,services,GitHub,CRITICAL,MEDIUM,regex,github]oedc7c96fd73c56fce9b5,regex,"(?i:github|client[-_]?id)(?:\R|.){0,40}(?<ID>\b([a-f0-9]{20})\b)"
secrets.services.github_pat.github_pat,github_pat,services,GitHub,CRITICAL,MEDIUM,regex,ghp_nZMcJU6t6X4DwgS3X7HeFCHrMZP2wXbAXKMK,regex,"(?<REGEX>(ghp_[a-zA-Z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}|\b((gho|ghu|ghs|ghr)_[a-zA-Z0-9_]{36,255})\b))"
secrets.services.gitlab_agent.gitlab_agent,gitlab_agent,services,GitLab,CRITICAL,MEDIUM,regex,agent_tokenoJ6MfV9vmEKw_Jj5L264YxZ86gyHZFNM2LH5MI5nNl6PZh1iZMLFL,regex,"(?i:config\.token|agent[-_]?token)(?:\R|.){0,40}(?<REGEX>\b([A-Za-z0-9-_]{50})\b)"
secrets.services.gitlabv2.gitlabv2,gitlabv2,services,GitLab,CRITICAL,MEDIUM,regex,glpat-nlbAH9_AiQjAp3PHhgNw,regex,"(?<REGEX>(glpat-[a-zA-Z0-9\-=_]{20,22}))"
secrets.services.gnews.gnews,gnews,services,GNews,INFO,MEDIUM,regex,"gnews


89bbf8921a3d33b03c2aea76b9d56f3d",regex,"(?i:gnews|token|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.godaddy.godaddy,godaddy,services,GoDaddy,CRITICAL,MEDIUM,regex,Uci63prSma6whudk0HBYBb,regex,(?<SECRET>\b[0-9A-Z][0-9A-Za-z]{21}\b)
secrets.services.google_api.google_api,google_api,services,Google Cloud,WARNING,MEDIUM,regex,AIzaSqOE9bZOvXPQnXeNDd7uJvvaFAqr27y-EjB,regex,(?<REGEX>AIzaS[A-Za-z0-9_-]{34})
secrets.services.google_cloud_storage.google_cloud_storage,google_cloud_storage,services,Google Cloud,CRITICAL,MEDIUM,regex,lDrv_VhDCa+GEAfwu3yPEGc+7ToCkd1O+gllpADd,regex,(?<SECRET>\b([A-Za-z0-9-_\/+]{40})\b)
secrets.services.google_oauth_short_lived.google_oauth_short_lived,google_oauth_short_lived,services,Google Cloud,CRITICAL,MEDIUM,regex,ya29.p_ecfLekI_CxkOknrZ6e,regex,"(?<REGEX>ya29\.[a-zA-Z0-9_-]{20,})"
secrets.services.grafana_service_token-nv.grafana_service_token_nv,grafana_service_token_nv,services,Grafana,ERROR,MEDIUM,regex,glsa_MgPLy97Zl2uvlLPf05749WwWhx7mW4eS_21wuYbH9,regex,(?<TOKEN>glsa_[A-Za-z0-9]{32}_[A-Za-z0-9]{8})
secrets.services.grafana_service_token.grafana_service_token,grafana_service_token,services,Grafana,ERROR,MEDIUM,regex,glsa_v5qgtuN2TflrOUHy75pJcCYvQ0zRgMDJ_dGVJE74Z,regex,(?<TOKEN>glsa_[A-Za-z0-9]{32}_[A-Za-z0-9]{8})
secrets.services.grafbase.grafbase,grafbase,services,Grafbase,ERROR,MEDIUM,regex,eyJ4ihL.eyJVGZI.f,regex,(?<REGEX>eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+)
secrets.services.harness-sat.harness-sat,harness-sat,services,Harness,ERROR,MEDIUM,regex,sat.Pw6_BlAZVYWCaJ__Aqw15r.0b3d089af8340915732b45d2.yj2Xp7CzCt5s0DpS1awM,regex,(?<REGEX>\bsat\.([A-Za-z0-9-_]{22}\.[a-f0-9]{24}\.[A-Za-z0-9-_]{20}|[a-f0-9]{24}\.[A-Za-z0-9-_]{20})\b)
secrets.services.hashicorp-vault-auth.hashicorp-vault-auth,hashicorp-vault-auth,services,HashiCorp,CRITICAL,MEDIUM,regex,"secret_id
0cc06872-4eec-689c-d3d3-73065425828a",regex,"(?i:secret[-_]?id)(?:\R|.){0,40}(?<SECRET>\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b)"
secrets.services.hashicorp-vault-token.hashicorp-vault-token,hashicorp-vault-token,services,HashiCorp,ERROR,MEDIUM,regex,hvs.CAESIg-1G_F34QpMFqis5OCRFRmithbqtkxmIjrKdiE0uJ-EDdbNA5FI71y30BunskJMQnSdvtyAcODCyFsgxasORyZrYULtkuKzZNg,regex,"(?<REGEX>hvs\.CAESI[A-Za-z0-9-_]{98,101})"
secrets.services.hcaptcha-siteverify.hcaptcha-siteverify,hcaptcha-siteverify,services,HCaptcha,ERROR,MEDIUM,regex,ES_3954a3c3f3e5b6261720230beea42108,regex,(?<REGEX>ES_[a-f0-9]{32})
secrets.services.heroku-token.heroku-token,heroku-token,services,Heroku,CRITICAL,MEDIUM,regex,HRKU-AAwbDGF22v1TdffOiZJIKY4nqn6uudVVZ0n2ziMUX2VoHzpFqlI0cKGMLvYU,regex,(?<REGEX>HRKU-AA[0-9a-zA-Z_-]{58})
secrets.services.huggingface-base64.huggingface-base64,huggingface-base64,services,Huggingface,ERROR,MEDIUM,regex,aGZfkEuBfeOBAUNNjrGAnM5YoBbmMGn7T02m/YRiw1SFnJg3W==,regex,"(?<REGEX>\b(aGZf[A-Za-z0-9+\/]{45,}={1,2}))"
secrets.services.huggingface-legacy.huggingface-legacy,huggingface-legacy,services,Huggingface,CRITICAL,MEDIUM,regex,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,regex,(?<REGEX>api_org_[a-zA-Z]{34})
secrets.services.huggingface.huggingface,huggingface,services,Huggingface,CRITICAL,MEDIUM,regex,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,regex,(?<REGEX>hf_[a-zA-Z]{34})
secrets.services.humeai-apikey.humeai-apikey,humeai-apikey,services,HumeAI,INFO,MEDIUM,regex,"apikeyd2
3bj8rP4dM5WcvOykrpw8FUsBvkFo0dCEIddyMbEdj02UBAZpB",regex,"(?i:api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([0-9A-Za-z]{48})\b)"
secrets.services.humeai-secret.humeai-secret,humeai-secret,services,HumeAI,WARNING,MEDIUM,regex,secret-keyAmn6oqFfkiGDPPcXcfWBUt4VmgFKCawrkQJKFXwRi6DAaOlSc75xHXRE8bHbyqVoWk,regex,"(?i:secret[-_]?key)(?:\R|.){0,40}(?<SECRET>\b([0-9A-Za-z]{64})\b)"
secrets.services.invoiceocean.invoiceocean,invoiceocean,services,InvoiceOcean,ERROR,MEDIUM,regex,apitokenZQQyA2JOVo5s7r/O3/9WgG2,regex,"(?i:api[-_]?token)(?:\R|.){0,40}(?<SECRET>\b([0-9A-Za-z\/]{20,30})\b)"
secrets.services.ipapi.ipapi,ipapi,services,IPAPI,INFO,MEDIUM,regex,apikeyb049966a8095aa081ffadc1f6c366aec,regex,"(?i:ipapi|access[-_]?key|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.ipinfo.ipinfo,ipinfo,services,IPinfo,INFO,MEDIUM,regex,"tokenbqJ
728120661908e9",regex,"(?i:token|ipinfo)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{14})\b)"
secrets.services.ipstack.ipstack,ipstack,services,IPstack,INFO,MEDIUM,regex,api_keyl2fa3995069d8e92a675b39ea4beb2657,regex,"(?i:ipstack|api[-_]?key|access[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.iterable.iterable,iterable,services,Iterable,WARNING,MEDIUM,regex,apikeyTbb71b827daff33f5df55d3f8186d4ea6,regex,"(?i:iterable|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.iyzipay.iyzipay,iyzipay,services,Iyzico,CRITICAL,MEDIUM,regex,iyzipaymsandbox-lMnJP7coVndq18Noa8JaOhLuUIK7MsHi,regex,"(?i:iyzipay|iyzico|secret[-_]?key)(?:\R|.){0,40}(?<SECRET>\b((sandbox-)?[A-Za-z0-9]{32})\b)"
secrets.services.jfrog_access_token.jfrog_access_token,jfrog_access_token,services,Jfrog,CRITICAL,MEDIUM,regex,eyJQf-3B.eyJx8d.hwkHU2,regex,(?<SECRET>\beyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\b)
secrets.services.jfrog_api_key.jfrog_api_key,jfrog_api_key,services,Jfrog,CRITICAL,MEDIUM,regex,AKCxChyqvNSPNSobrMVcneGt93ynTaGuWMSdnEBE1wEWf9zKmtQZlHIBsdmX961pueNgKZqcj,regex,(?<SECRET>AKC[a-zA-Z0-9]{70})
secrets.services.jfrog_id_token.jfrog_id_token,jfrog_id_token,services,Jfrog,ERROR,MEDIUM,regex,cmVmdbNhTjZWikc0F8qbTjbI3y3IcOiSpbaZ0ljvBeI2SMiMgkzVaATLHdthXdwk,regex,(?<SECRET>cmVmd[a-zA-Z0-9]{59})
secrets.services.jina.jina,jina,services,Jina,ERROR,MEDIUM,regex,jina_a61e1432485ee2ed773e05953aef3b83lJqUWALVyuscvEPYaZ4IQFc8zSeO,regex,(?<REGEX>jina_[0-9a-f]{32}[0-9A-Za-z-_]{28})
secrets.services.kieai.kieai,kieai,services,KieAI,WARNING,MEDIUM,regex,key48bb2914071b379d926fb7ec9e70f07c,regex,"(?i:key|token|bearer)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.kylas.kylas,kylas,services,Kylas,WARNING,MEDIUM,regex,"bearer

073c282d-3e8e-c262-cd00-c0432ae07885:65636",regex,"(?i:kylas|bearer|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}:[0-9]{3,5})\b)"
secrets.services.larksuite-appsecret.larksuite-appsecret,larksuite-appsecret,services,Larksuite,ERROR,MEDIUM,regex,"secretZ

z2lsZjwsRC2io697WIYOqQsO3JSSlGI7",regex,"(?i:secret)(?:\R|.){0,40}(?<SECRET>\b([a-z0-9A-Z]{32})\b)"
secrets.services.lemlist.lemlist,lemlist,services,Lemlist,WARNING,MEDIUM,regex,"api_key
78c08d731e2338cfc63fcc93cd728437",regex,"(?i:api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.loadmill.loadmill,loadmill,services,Loadmill,WARNING,MEDIUM,regex,"keyZ
d WkDIVaxq6hrav0a6XhtNMfOaArFkdplVsdexx20s",regex,"(?i:key|bearer)(?:\R|.){0,40}(?<REGEX>\b([0-9a-zA-Z]{40})\b)"
secrets.services.mailchimp.mailchimp,mailchimp,services,Mailchimp,WARNING,MEDIUM,regex,a109c00a385054803e11d7b70c4f03cd-us6,regex,"(?<REGEX>(?P<TOKEN>\b[0-9a-f]{32})-(?<REGION>us[0-9]{1,2}))"
secrets.services.mailersend.mailersend,mailersend,services,Mailersend,WARNING,MEDIUM,regex,mlsn.15dfb7e58051f1c2e25576ccdd92d1b8b847af7085ab4e704c3e59fd96339e52,regex,(?<REGEX>(mlsn\.[a-f0-9]{64}))
secrets.services.meilisearch.meilisearch,meilisearch,services,Meilisearch,WARNING,MEDIUM,regex,27787691f0f4aa8c18d90bfae2be24a53bbaf353,regex,(?<REGEX>\b([a-f0-9]{40})\b)
secrets.services.mem0.mem0,mem0,services,Mem0,ERROR,MEDIUM,regex,m0-GrYE0JB5xQI9rMTZnvDiIMDQZrpWmPH4KIFZrAkw,regex,(?<REGEX>m0-[A-Za-z0-9]{40})
secrets.services.mercadopago-oauth.mercadopago-oauth,mercadopago-oauth,services,MercadoPago,CRITICAL,MEDIUM,regex,"client-secret
Jo0KqsXzlExV9djTfxbYCOI25vWVtJAJ",regex,"(?i:client[-_]?secret)(?:\R|.){0,40}(?<SECRET>\b([A-Za-z0-9]{32})\b)"
secrets.services.mercadopago.mercadopago,mercadopago,services,MercadoPago,CRITICAL,MEDIUM,regex,APP_USR-7336597814780107-447874-7bf4c7a80572ccee827fc1d1923e249c-05080466,regex,"(?<REGEX>(APP_USR-[0-9]{16}-[0-9]{6}-[a-f0-9]{32}-[0-9]{7,10}))"
secrets.services.messagebird.messagebird,messagebird,services,Messagebird,WARNING,MEDIUM,regex,"messagebird
mwShED0K5uvJiMIhIbKWHo2ELA",regex,"(?i:messagebird)(?:\R|.){0,40}(?<REGEX>\b[A-Za-z0-9]{25}\b)"
secrets.services.mindmeister.mindmeister,mindmeister,services,Mindmeister,WARNING,MEDIUM,regex,"bearer
UXd6cPckcy3qDAIzOF1cmAakcB2h7N6rvAXdJvgaJkfD",regex,"(?i:mindmeister|bearer)(?:\R|.){0,40}(?<REGEX>\b([a-zA-Z0-9]{43})\b)"
secrets.services.minimax.minimax,minimax,services,MiniMax,WARNING,MEDIUM,regex,sk-api-EsxVsMvcIeQMMf_Hi2nP55wmV52e9Wrkf8CHnVElDlkybZeRzY7E5hn4lHvo26osXcPqXweDU6h7IigixLqPe58vOizwhRx8ePVtNxcma8qmB1doDiHdyRw,regex,(?<REGEX>sk-api-[A-Za-z0-9-_]{119})
secrets.services.minio-license.minio-license,minio-license,services,MinIO,ERROR,MEDIUM,regex,eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9.eyJpBG.jz5,regex,(?<REGEX>eyJhbGciOiJFUzM4NCIsInR5cCI6IkpXVCJ9\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+)
secrets.services.minio.minio,minio,services,MinIO,ERROR,MEDIUM,regex,"secretkeyg

faEVh0pAP5rHGR4mF/cOPm3Qf5tVvXJoDP=/ng2g",regex,"(?i:secret[-_]?key)(?:\R|.){0,40}(?<SECRET>\b([A-Za-z0-9/+=]{40})\b)"
secrets.services.mistral.mistral,mistral,services,Mistral,WARNING,MEDIUM,regex,"key
>i01IgdwYylDvqs43cx93wP8WZV6AlylD",regex,"(?i:key|bearer)(?:\R|.){0,40}(?<REGEX>\b([A-Za-z0-9]{32})\b)"
secrets.services.modelscope.modelscope,modelscope,services,ModelScope,WARNING,MEDIUM,regex,ms-9392864e-a7bb-d52f-ca74-2065729c5c34,regex,(?<REGEX>ms-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})
secrets.services.moderation.moderaion,moderaion,services,Moderation,INFO,MEDIUM,regex,eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6mPF-.H,regex,(?<REGEX>\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.eyJpZCI6[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\b)
secrets.services.momo-apikey.momo-apikey,momo-apikey,services,MTN,CRITICAL,MEDIUM,regex,"api
FttTU9sZz6ppaQB4zWc6aRjwqgh7IrHd",regex,"(?i:api)(?:\R|.){0,40}(?<REGEX>\b([a-zA-Z0-9]{32})\b)"
secrets.services.momo-subscription.momo-subscription,momo-subscription,services,MTN,CRITICAL,MEDIUM,regex,subscriptionP#61341fbb35a5c197d340890975ffded5,regex,"(?i:subscription)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.momo-token.momo-token,momo-token,services,MTN,CRITICAL,MEDIUM,regex,eyJ0eXAiOiJKV1QiLCJhbGciOiJSMjU2In0.eyJjbGllbnRJZCI6II.-M,regex,(?<REGEX>eyJ0eXAiOiJKV1QiLCJhbGciOiJSMjU2In0\.eyJjbGllbnRJZCI6I[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+)
secrets.services.murf.murf,murf,services,Murf,WARNING,MEDIUM,regex,ap2_2f2b6da0-870d-a1c7-e4b8-129ba2c123a6,regex,(?<REGEX>ap2_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})
secrets.services.myintervals.myintervals,myintervals,services,MyIntervals,WARNING,MEDIUM,regex,myintervalsb4lbbf6pt4s,regex,"(?i:myintervals)(?:\R|.){0,40}(?<REGEX>\b([a-z0-9]{11})\b)"
secrets.services.neoload.neoload,neoload,services,Tricentis,WARNING,MEDIUM,regex,"tokenb

212063434b99ba1edd1d4d49e11b1a7f1cff64fb34d0dc4f",regex,"(?i:neoload|token|key)(?:\R|.){0,40}(?<REGEX>\b[a-f0-9]{48}\b)"
secrets.services.newrelic-api-key.newrelic-api-key,newrelic-api-key,services,New Relic,ERROR,MEDIUM,regex,NRAK-UAGEHDYjeuh7STjXq879KoOXoQD,regex,(?<REGEX>NRAK-[A-Za-z0-9]{27})
secrets.services.newrelic-license-key.newrelic-license-key,newrelic-license-key,services,New Relic,WARNING,MEDIUM,regex,73887ea88ffbdacc67014290d3aa99a1BBCENRAL,regex,(?<REGEX>\b[a-f0-9]{32}[A-F]{4}NRAL\b)
secrets.services.nimble.nimble,nimble,services,Nimble,WARNING,MEDIUM,regex,"nimbleA
Ux18RB7QV0RBJdx7ofeuaxsL2VjFzM",regex,"(?i:nimble)(?:\R|.){0,40}(?<REGEX>\b([a-zA-Z0-9]{30})\b)"
secrets.services.notion.notion,notion,services,Notion,ERROR,MEDIUM,regex,secret_KUUsc6aFVEwcclm1HR4e6ZmD4wfEtp82OKQogu0HHsn,regex,(?<REGEX>\b(secret_[A-Za-z0-9]{43})\b)
secrets.services.npm_tokenv2.npm-tokenv2,npm-tokenv2,services,npm,CRITICAL,MEDIUM,regex,npm_xoTounzCLGcms1kJwpIbDbTkWzU4VXp88Q7n,regex,(?<REGEX>\b(npm_[0-9a-zA-Z]{36})\b)
secrets.services.nuget.nuget,nuget,services,NuGet,CRITICAL,MEDIUM,regex,"nuget,
k8p9894gwxdf1wo9c4ihqxhw4ufm3lsr07qxtj5ohy4rls",regex,"(?i:nuget)(?:\R|.){0,40}(?<REGEX>\b([a-z0-9]{46})\b)"
secrets.services.nutritionix.nutritionix,nutritionix,services,Nutritionix,INFO,MEDIUM,regex,"app_key


b9c97e7b9297f29d725492d2863f91a0",regex,"(?i:(app|api)[-_]?key)(?:\R|.){0,40}(?<SECRET>\b([a-f0-9]{32})\b)"
secrets.services.octopus_deploy.octopus-deploy,octopus-deploy,services,Octopus Deploy,CRITICAL,MEDIUM,regex,API-a]]]]]]]]]]]]]]]]]]]]]]]]]]]]],regex,"(?<KEY>\bAPI-[[:alnum:]]{29,32}\b)"
secrets.services.odoo.odoo,odoo,services,Odoo,ERROR,MEDIUM,regex,10a7d555045cf8662cdf8f453b405bec5db1bf0d,regex,(?<KEY>\b([a-f0-9]{40})\b)
secrets.services.okta-oauth-token.okta-oauth,okta-oauth,services,Okta,CRITICAL,MEDIUM,regex,"okta_token = ""eyJraWQiOiJXbUhicjhCcS1YV3JVRDMxYUxSUFdFY3RXQm5jczRmSyIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIwMHUxOTAwMDAwMDAwMDA0aDh6MnMzWiIsInVpZCI6IjAwdTE5MDAwMDAwMDAwMDRoOHoyczNaIn0.aBcDeFgHiJkLmNoPqRsTuVwXyZ""",manual,(?<REGEX>eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+)
secrets.services.okta-oauth.okta-oauth,okta-oauth,services,Okta,CRITICAL,MEDIUM,regex,"secret



]L2dHKuxe9DC9GI2DLW-PMcvOBquLcGLojvZO28IDcgHkEiRMfkPr1EqJk3CBcWz1",regex,"(?i:secret)(?:\R|.){0,40}(?<SECRET>\b([a-zA-Z0-9-_]{64})\b)"
secrets.services.onelogin-oauth.onelogin-oauth,onelogin-oauth,services,OneLogin,ERROR,MEDIUM,regex,client-secret+5e39d947be6ff303dc86b36b53443e68353f6e842eb0c8e25cec61e8469c92db,regex,"(?i:client[-_]?secret)(?:\R|.){0,20}(?<SECRET>\b([a-f0-9]{64})\b)"
secrets.services.onesignal-app.onesignal-app,onesignal-app,services,OneSignal,WARNING,MEDIUM,regex,os_v2_app_4igDiDFK75BOQYX81G5unE2D7MNiFZENBWPcGjNEnQltkesMc8RHEvphJp2Zq0IxOJRYP1SbriQtagDWwliFs8zKO958ejIlOogdfex,regex,(?<KEY>(os_v2_app_[0-9a-zA-Z]{103}))
secrets.services.openai.openai,openai,services,OpenAI,CRITICAL,MEDIUM,regex,sk-IRT3BlbkFJf4_hczw9JNdSOSa5R6-N,regex,"(?<REGEX>(sk-([a-zA-Z0-9-_]+)T3BlbkFJ[A-Za-z0-9-_]{20,}))"
secrets.services.openclaw.openclaw,openclaw,services,OpenClaw,CRITICAL,MEDIUM,regex,"tokent

H:a02b46c339a5b1314e27afa05f88cd1362bc552fcbf1d59b8839ca37802e5ed5",regex,"(?i:token)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{64})\b)"
secrets.services.openrouter.openrouter,openrouter,services,OpenRouter,ERROR,MEDIUM,regex,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,regex,(?<REGEX>sk-or-v1-[a-f0-9]{64})
secrets.services.openvpn-jwt.openvpn-jwt,openvpn-jwt,services,OpenVPN,ERROR,MEDIUM,regex,eyJOc4fit.eyJeMMA-c.id,regex,(?<REGEX>\beyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\b)
secrets.services.openvpn.openvpn,openvpn,services,OpenVPN,ERROR,MEDIUM,regex,AlWGbqHdSlGq2cmPDc9qWqL0GMhZx8DcImKtkiGZyaV1iCMKyabJX2Zpr6O0IXTL,regex,(?<SECRET>\b([a-zA-Z0-9]{64})\b)
secrets.services.opsgenie.opsgenie,opsgenie,services,Opsgenie,WARNING,MEDIUM,regex,"api-keyz
82f670ef-cb1b-4ea9-d219-67fcdb0433c6",regex,"(?i:opsgenie|genie[-_]?key|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b)"
secrets.services.overloop.overloop,overloop,services,Overloop,WARNING,MEDIUM,regex,"overloop
B

BKSpbawKlqOKvLasLUSSaPrhgB-hSdfKk4EpfZJGO_g71Sa8Q8",regex,"(?i:overloop)(?:\R|.){0,40}(?<REGEX>\b([A-Za-z0-9-_]{50})\b)"
secrets.services.paddle.paddle,paddle,services,Paddle,ERROR,MEDIUM,regex,pdl_sdbx_apikey_\cr5jsVK5oplYpdY3jNLf9cBmD_srBpiwlMio5gkm^5awQE2sE_fy,regex,(?<REGEX>pdl_(sdbx|live)_apikey_[a-zA-z0-9]{26}_[a-zA-z0-9]{26})
secrets.services.pagar-sandbox.pagar-sandbox,pagar-sandbox,services,Pagar,INFO,MEDIUM,regex,sk_test_98409173b8c1255a19614de3d38e77d4,regex,(?<REGEX>sk_test_[a-f0-9]{32})
secrets.services.pagar.pagar,pagar,services,Pagar,CRITICAL,MEDIUM,regex,sk_0c6c42bba3fdd1e9af35fc176b098ea1,regex,(?<REGEX>sk_[a-f0-9]{32})
secrets.services.partnerstack.partnerstack,partnerstack,services,PartnerStack,ERROR,MEDIUM,regex,"partnerstack


Q#uLX1sk4L5vRRn9v6u8tmFBCdfVWYHNVuA5pO85cG23aCJAIjULh98IuhDqjl9jql",regex,"(?i:partnerstack)(?:\R|.){0,40}(?<REGEX>\b([0-9A-Za-z]{64})\b)"
secrets.services.paydirtapp.paydirtapp,paydirtapp,services,Paydirt,WARNING,MEDIUM,regex,paydirtapp2b13505d174cc9bc9642965d8e519eae,regex,"(?i:paydirtapp|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.pdflayer.pdflayer,pdflayer,services,Pdflayer,INFO,MEDIUM,regex,"pdflayer
0d02a7d901311f375990527fe7cbb1ae",regex,"(?i:pdflayer|key|token)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.pepipost.pepipost,pepipost,services,Pepipost,WARNING,MEDIUM,regex,api-keypcf48485dad5154cef256de36c10b13b7,regex,"(?i:api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.pinecone.pinecone,pinecone,services,Pinecone,ERROR,MEDIUM,regex,pcsk_v3Do7y_kRBFoxuul4GyEQc2q1IRKC224ipbWX73kl7G6GKIlaHpihtosXIwqFpwTsRv,regex,"(?<REGEX>pcsk_[0-9A-Za-z]{6}_[0-9A-Za-z]{60,80})"
secrets.services.pipedream-oauth.pipedream-oauth,pipedream-oauth,services,Pipedream,WARNING,MEDIUM,regex,clientsecretTbR5t_Ic42eiBp2D-DGqGvp9-0IE_Uh1GdeFU8kPmSIO,regex,"(?i:client[-_]?secret)(?:\R|.){0,10}(?<SECRET>\b([A-Za-z0-9_-]{43})\b)"
secrets.services.pipedream-token.pipedream-token,pipedream-token,services,Pipedream,WARNING,MEDIUM,regex,eyJ5qnf.Ex.VqxUcn,regex,(?<REGEX>eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+)
secrets.services.pipedream.pipedream,pipedream,services,Pipedream,WARNING,MEDIUM,regex,"pipedream':l
bb0ce8407e435f50021799dcf55c7ab2",regex,"(?i:pipedream|token|bearer)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.planyo.planyo,planyo,services,Planyo,WARNING,MEDIUM,regex,"api_key



w6759aed5e0c8a10152665374ff2e1e71869480a94f392a0782a9ee72e900d7",regex,"(?i:planyo|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([0-9a-f]{62})\b)"
secrets.services.plivo.plivo,plivo,services,Plivo,WARNING,MEDIUM,regex,keyfGLwDcgmU8-NAkhgJ_l8fIvJzxgw0Im4lJhHPEgRg,regex,"(?i:token|key|secret)(?:\R|.){0,40}(?<TOKEN>\b([A-Za-z0-9_-]{40})\b)"
secrets.services.polar-customer.polar-customer,polar-customer,services,Polar,CRITICAL,MEDIUM,regex,polar_cst_uf6xzbYSaPt8yqWqJIncMW4BUMCRXj636nnnIswppA6,regex,(?<REGEX>polar_cst_[A-Za-z0-9]{43})
secrets.services.polar.polar,polar,services,Polar,WARNING,MEDIUM,regex,polar_oat_k4VHLdVN4zDilWAHUXnrlJW5tYR8UNs86OUpJOooJCY,regex,(?<REGEX>polar_oat_[A-Za-z0-9]{43})
secrets.services.postman.postman,postman,services,Postman,CRITICAL,MEDIUM,regex,PMAK-ee3112cc3fc0cbface4bbcac-11c39750b258207e8febc6b925e7c7d6d4,regex,(?<REGEX>(PMAK-[a-f0-9]{24}-[a-f0-9]{34}))
secrets.services.postmark-account-token.postmark-account-token,postmark-account-token,services,Postmark,WARNING,MEDIUM,regex,"postmarkapp
5b36387a3-c2ac-ba67-7378-f613c3cf7ac4",regex,"(?i:postmarkapp|account[-_]?token)(?:\R|.){0,40}(?<REGEX>\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b)"
secrets.services.postmark.postmark,postmark,services,Postmark,WARNING,MEDIUM,regex,"postmarkapp
878783dd-ad3e-369e-a830-7cb5545f1437",regex,"(?i:postmarkapp|key|server[-_]?token)(?:\R|.){0,40}(?<REGEX>\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b)"
secrets.services.prefect.prefect,prefect,services,Prefect,ERROR,MEDIUM,regex,pnu_4bW1hkZ8OPDMieIOmeWGNcps0hhbbxbybzNx,regex,(?<REGEX>\b(pnu_[a-zA-Z0-9]{36})\b)
secrets.services.pubnub-publishkey.pubnub-publishkey,pubnub-publishkey,services,PubNub,WARNING,MEDIUM,regex,pub-c-4a6d4728-4e78-8a0f-8f07-80f739983423,regex,(?<PUB>\b(pub-c-[0-9a-f]{8}-[0-9a-f]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b)
secrets.services.pubnub-secretkey.pubnub-secretkey,pubnub-secretkey,services,PubNub,WARNING,MEDIUM,regex,sec-c-uVINneGJJZSl4siMEAr4e3uBGezxIzQpEDx3ONGYxjar15Tp,regex,(?<REGEX>\b(sec-c-[0-9A-Za-z]{48})\b)
secrets.services.pydantic-ai-gateway.pydantic-ai-gateway,pydantic-ai-gateway,services,Pydantic,ERROR,MEDIUM,regex,paig_4zta4Utstqb1BYG2yC4aV23QcfFmjU5s,regex,(?<REGEX>paig_[A-Za-z0-9]{32})
secrets.services.pypi.pypi,pypi,services,PyPI,CRITICAL,MEDIUM,regex,pypi-AgEIcHlwaS5vcmcn1qGOrJilhOKBStt2J1tRfflznlFfr9zdIlzSh0oRLtKcMT8bY,regex,"(?<REGEX>(pypi-AgEIcHlwaS5vcmc[a-zA-Z0-9-_]{50,208}))"
secrets.services.rechargepayments.rechargepayments,rechargepayments,services,RechargePayments,CRITICAL,MEDIUM,regex,apikeyjN)mYsk_10x1_34F7D25cCf291aEf5474cFf4eF38C39cCB16aFE8DE5da17DF8CCaBD07aF37eB9,regex,"(?i:access[-_]?token|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\bsk(_test)?_(1|2|3|5|10)x[123]_[0-9a-fA-F]{64}\b)"
secrets.services.resend.resend,resend,services,Resend,WARNING,MEDIUM,regex,re_z8KE9jd0_ib5DnF6ucHaDO5R9YhnhnI1J,regex,(?<REGEX>re_[0-9A-Za-z]{8}_[0-9A-Za-z]{24})
secrets.services.restpack-html2pdf.restpack-html2pdf,restpack-html2pdf,services,Restpack,WARNING,MEDIUM,regex,tokenqQhOHsfc8HgrvuUfdj5D6WcfhilzmgkEgUESt6zgCk7p4UdM,regex,"(?i:restpack|token)(?:\R|.){0,40}(?<REGEX>\b([a-zA-Z0-9]{48})\b)"
secrets.services.retell.retell,retell,services,Retell,ERROR,MEDIUM,regex,key_6a4747b3f70ad1b49e8978ce137b,regex,(?<REGEX>key_[a-f0-9]{28})
secrets.services.ringcentral-accesstoken.ringcentral-accesstoken,ringcentral-accesstoken,services,RingCentral,WARNING,MEDIUM,regex,"token!yx
DyWH3b4sr7ZOvJ5ApRAhtHJLMbVIdLNZmET10tTgHqzheqooZNNCURMmHQSZKbQdcjeRBoG2pJghTbfixhPV5Kz87Alu0aUg6HvuuLmKRi5xZ0B47mVcBzWdehswyQtHuFoOwoAFzW2xdxqFsPzkMabXSDQjfCDx1n7I1oKAVX7B1c1wyqVie6DiARg0YUHuLOspCGpFX7sM3XvvJFW3mRKBOk4RpFdo4i5TRVrOxjoC018W6dvpL8P0vPR1rdggMSgUs8X3dFwbMnq9FH2JWc9XijlgEVTmbpxPXBSBsZMs",regex,"(?i:token)(?:\R|.){0,40}(?<REGEX>\b([A-Za-z0-9]{300,400})\b)"
secrets.services.ringcentral.ringcentral,ringcentral,services,RingCentral,WARNING,MEDIUM,regex,"clientsecret

Mxd8rc5Ii1UzGbko60QiCrKjtFKLAOPhHF7FzGeGxZtkx",regex,"(?i:client[-_]?secret)(?:\R|.){0,40}(?<SECRET>\b([0-9A-Za-z]{44})\b)"
secrets.services.rollbar.rollbar,rollbar,services,Rollbar,WARNING,MEDIUM,regex,rollbarff2d848f0ad2b1793461743aed1962a5d38fef3f0469a5dda35bd3697ea2b84d0324f18788461c001b8142274efba03f,regex,"(?i:rollbar)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{96})\b)"
secrets.services.roninapp.roninapp,roninapp,services,Ronin,INFO,MEDIUM,regex,"apikey

q
PmSK6q8Bhjwl4ZD4jeknQbzL5YW",regex,"(?i:roninapp|api[-_]?key|api[-_]?token)(?:\R|.){0,40}(?<KEY>\b([0-9a-zA-Z]{24,26})\b)"
secrets.services.sanity.sanity,sanity,services,Sanity,WARNING,MEDIUM,regex,sanitysk7OhlYlFFsUutY2MN0p4jfdPBKTBpqp1XYlgUBUaJqYfayma1cNdVPSqHqZKoXVVlUZJIUWpwLXTxWp,regex,"(?i:sanity)(?:\R|.){0,40}(?<REGEX>\b(sk[A-Za-z0-9]{78,178})\b)"
secrets.services.scalr.scalr,scalr,services,Scalr,ERROR,MEDIUM,regex,"scalr_token = ""eyJwYXlsb2FkIjoie1wibmFtZVwiOlwic2NhbHItYXBpXCJ9In0.eyJPMj4xNTE2MjM5MDIyLCJqdGkiOiJhYmMxMjMifQ.SignatureBytesGoHere""",manual,(?<TOKEN>\beyJ[0-9A-Za-z]+\.eyJ[0-9A-Za-z]+\.[A-Za-z0-9_-]+\b)
secrets.services.scraperapi.scraperapi,scraperapi,services,ScraperAPI,INFO,MEDIUM,regex,"apikey


`
2ulo1yc1wn4x13kyul0bh7sj1hrf02p6",regex,"(?i:scraperapi|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-z0-9]{32})\b)"
secrets.services.scrapestack.scrapestack,scrapestack,services,Scrapestack,INFO,MEDIUM,regex,"key_cc
53b99c2532ca98b6cc868aecb43a76d0",regex,"(?i:scrapestack|key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.semantic.constant-folding.huggingface.huggingface,huggingface,services,Huggingface,CRITICAL,MEDIUM,js;ts;python;java;golang,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,regex,(?<REGEX>hf_[a-zA-Z]{34})
secrets.services.sendgrid.sendgrid,sendgrid,services,SendGrid,WARNING,MEDIUM,regex,SG.f-DïtUÓì5Ü¹ÎíªGêSùÔî_bþ.oêTÀpÐ7ÝªïhÝ24ÂÔStrjóaþÌJÙIâ²1CrIêâ2F¹Ø,regex,"(?<REGEX>\b(SG\.[\w\-_]{20,24}\.[\w\-_]{39,50})\b)"
secrets.services.shutterstock.shutterstock,shutterstock,services,Shutterstock,WARNING,MEDIUM,regex,v2/G4ZoTtvZCw8psn07sXtWbujKYBUiiGcJbITKuWrKIhNOtMSXrpxXK3PQ13XZ6lW6ybHhaOWbsvn0hqLKgHUk0MrhIL9wO5DYdD85zdIFGetO6OIOiCQcVYuzBuBulgcE5P5vRdUQXGB2TNXA7UjdgT6cWH6htRFgKhg993t9uriDM70e0zmGeyzTqiOBwDzfycqA9PeYqPpxwmX1PaUrZo6yefLK8oetAxe7kSbY5wbAO85c1L6BoLUS3hxnaP5mzQkW2gDdbwIgJzTZHwvxZBZZYYeljVykOEjOtkLFlJL2Yt5wLbY8lTfoA8SnT5JIcWIRLNVAzr7GCwaHhaxPNHyjFxGPCWuKo62gP24fQ282chW00uTehtHuqV1ORPR39l8R,regex,(?<REGEX>\b(v2/[0-9A-Za-z]{388})\b)
secrets.services.signalwire.signalwire,signalwire,services,SignalWire,WARNING,MEDIUM,regex,PT2d9517c95bfeaac5e994d6c8f5337da338bb395fcfb34808,regex,(?<KEY>\b(PT[0-9a-f]{48})\b)
secrets.services.signaturit.signaturit,signaturit,services,Signaturit,ERROR,MEDIUM,regex,signaturitrWH4NwB9Ri2Elg5jrG07i5m12a9bygv4HRsf9v23fpaCdummlSViECLcgABZTfXZ7JMTKDDiLfh69rYbFmR1tG,regex,"(?i:signaturit)(?:\R|.){0,40}(?<REGEX>\b([0-9A-Za-z]{86})\b)"
secrets.services.slack_app_token.slack_app_token,slack_app_token,services,Slack,ERROR,MEDIUM,regex,xapp-3-AEP4-5414-b35f7ab3d2be27b9f2e73cf7874981bbb639a06775bfd0db3b46e6d8f61536a6,regex,(?<REGEX>xapp-\d-[A-Z0-9]+-\d+-[a-f0-9]{64})
secrets.services.slack_bot_token.slack-bot-token,slack-bot-token,services,Slack,ERROR,MEDIUM,regex,xoxb-070172090613-300810844164,regex,"(?<REGEX>xoxb\-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9\-]*)"
secrets.services.slack_user_token.slack-user-token,slack-user-token,services,Slack,ERROR,MEDIUM,regex,xoxp-103996605909-962247545783RaRkm,regex,"(?<REGEX>xoxp\-[0-9]{10,13}\-[0-9]{10,13}[a-zA-Z0-9\-]*)"
secrets.services.slack_webhook.slack-webhook,slack-webhook,services,Slack,INFO,MEDIUM,regex,https://hooks.slack.com/services/TMQ7W/B39CHY/qA7oQQncyxOwyklXIb24JvE6,regex,"(?<REGEX>https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{23,25})"
secrets.services.smartsheet.smartsheet,smartsheet,services,Smartsheet,WARNING,MEDIUM,regex,"bearert

b4dTPlf9lGp1YiDciFbVFpck7dtuL3mHeJHhW",regex,"(?i:token|bearer|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-zA-Z0-9]{37})\b)"
secrets.services.smartystreets.smartystreets,smartystreets,services,SmartyStreets,INFO,MEDIUM,regex,"authtoken

dlkfe43nLNsIvYmeXksO",regex,"(?i:smarty|auth[-_]?token)(?:\R|.){0,40}(?<SECRET>\b([a-zA-Z0-9]{20})\b)"
secrets.services.spotify-token.spotify-token,spotify-token,services,Spotify,WARNING,MEDIUM,regex,"spotifyV
^BQ2bR4bYGbKGsxc9BAD5gTQ6wpPzfSPW_YzfyruWRg8FlXn0bzthG3UyxKCQoV",regex,"(?i:spotify|token|bearer)(?:\R|.){0,40}(?<REGEX>\bBQ[0-9A-Za-z-_]{60,}\b)"
secrets.services.spotify.spotify,spotify,services,Spotify,WARNING,MEDIUM,regex,secretx74d51930c4f90390a67f9a360e7757b5,regex,"(?i:secret)(?:\R|.){0,10}(?<SECRET>\b([a-f0-9]{32})\b)"
secrets.services.stabilityai.stabilityai,stabilityai,services,StabilityAI,ERROR,MEDIUM,regex,sk-PU9ji8hYgkH7Ig6wI-0tAtFZkJmTZ_ipJV9bko1jKOgBKEmQ,regex,"(?<REGEX>\bsk-[A-Za-z0-9-_]{48,50}\b)"
secrets.services.stackhawk.stackhawk,stackhawk,services,StackHawk,WARNING,MEDIUM,regex,hawk.j9rOuiFvMkGt3Ua6dWPa.v8Baz2zBQZol0PTa3jwS,regex,(?<REGEX>hawk\.[A-Za-z0-9]{20}\.[A-Za-z0-9]{20})
secrets.services.statuspage.statuspage,statuspage,services,Atlassian,WARNING,MEDIUM,regex,ATCTT3xFfG8D8EAQ6gBA68pJm-sWwQRkortJRB4ribYvU5D9Rb=-0LZRk3ue18oHG4R1Rc8_oniz5y8XvxkY2rEKWA/BSh3awBjebhSNNxA2mVv6La+j/8e+onndWnwUiiMtxFjOHxmAm1tiUP621cNnc4RVmygjw4E6GD/UV7icOLZ-zVEOJ6Z=P7oGqXQd,regex,(?<REGEX>ATCTT3xFfG[A-Za-z0-9+\/=_-]{173}=[A-Za-z0-9]{8})
secrets.services.statuspal.statuspal,statuspal,services,StatusPal,WARNING,MEDIUM,regex,uk_KamWRwsmV6v4YsEcqaXbnLgM0rsRinCy,regex,(?<REGEX>uk_[A-Za-z0-9]{32})
secrets.services.stripe-paymentintent.stripe-paymentintent,stripe-paymentintent,services,Stripe,CRITICAL,MEDIUM,regex,pi_zu5mCn9DTa00NXDoDsLTzDNK,regex,(?<PI>\b(pi_[a-zA-Z0-9]{24})\b)
secrets.services.stripe.stripe,stripe,services,Stripe,CRITICAL,MEDIUM,regex,sk_live_zUwVZcKnqtattBJpocj79l6am,regex,"(?<REGEX>[rs]k_live_[a-zA-Z0-9]{20,99})"
secrets.services.supabase-service.supabase-service,supabase-service,services,Supabase,ERROR,MEDIUM,regex,sb_secret_FAE5Jp1WPUTE8HGNcYsyhW_yJX_j3Gh,regex,(?<KEY>sb_secret_[A-Za-z0-9-_]{22}_[A-Za-z0-9-_]{8})
secrets.services.surveysparrow.surveysparrow,surveysparrow,services,SurverySparrow,WARNING,MEDIUM,regex,przR2jrtmF-AvVr-wy4V0PDgpDeDkN6AVyEdMOurfByr9PZEFXbEDl1YOquPAJZv0XriZtrtnuuk3V7pCi93Wh9G,regex,(?<REGEX>(pr[a-zA-Z0-9-_]{86}))
secrets.services.swell.swell,swell,services,Swell,WARNING,MEDIUM,regex,sk_zJMytxvXJbsechJ0amX7fVyvre5Mgcq9,regex,(?<KEY>sk_[A-Za-z0-9]{32})
secrets.services.swiftype-engine.swiftype-engine,swiftype-engine,services,Swiftype,WARNING,MEDIUM,regex,"swiftype(
q

gpV7bVWhb6gicBZJ2b7i",regex,"(?i:swiftype)(?:\R|.){0,40}(?<REGEX>\b([0-9A-Za-z-_]{20})\b)"
secrets.services.swiftype.swiftype,swiftype,services,Swiftype,WARNING,MEDIUM,regex,swiftype zFgzWhehV-cPxsJx_54W,regex,"(?i:swiftype)(?:\R|.){0,40}(?<REGEX>\b([0-9A-Za-z-_]{20})\b)"
secrets.services.tableau-token.tableau-token,tableau-token,services,Tableau,WARNING,MEDIUM,regex,v8lu66rG69uLuclob3m-8m|BS7f7GJY13MOMRQelGc-NM1aEJ-WHMqr|be8b978a-384c-ae1b-9eda-b3b32f99943f,regex,(?<TOKEN>([A-Za-z0-9-]{22}\|[A-Za-z0-9-]{32}\|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}))
secrets.services.tableau.tableau,tableau,services,Tableau,WARNING,MEDIUM,regex,FiiRgMvUYRBZts/Qt/EBif==:0N0gTPieG7laHbQ36K0EavpYirwEvN3O,regex,(?<SECRET>\b([A-Za-z0-9+\/]{22}==:[A-Za-z0-9]{32})\b)
secrets.services.tailscale-oauth.tailscale-oauth,tailscale-oauth,services,Tailscale,ERROR,MEDIUM,regex,tskey-client-4UjgHjhMQLUl12htE-bqyZPXbq79M6dGqSmW1Lx1ywI5Lxe9od,regex,"(?<REGEX>tskey-client-[0-9A-Za-z]{17}-[0-9A-Za-z]{32,33})"
secrets.services.tavus.tavus,tavus,services,Tavus,WARNING,MEDIUM,regex,"api-key&
cb1e645e16bd09fda48bd8b9c4e326cd",regex,"(?i:tavus|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.teamgate.teamgate,teamgate,services,Teamgate,WARNING,MEDIUM,regex,"teamgate
Qt2Bj56y1COq5ydKBS777WQBlJss0tj60zkuEV27u1KRGL0PJtqq4HMsS5WbgKYxccgot8VcENi1dcLt1",regex,"(?i:teamgate|key)(?:\R|.){0,40}(?<KEY>\b([a-zA-Z0-9]{80})\b)"
secrets.services.teamwork-spaces.teamwork-space,teamwork-space,services,Teamwork,WARNING,MEDIUM,regex,tknbv1_GFaUca1WUTyGXXn4KRMlxnlz7ALHohNaFBzUnV2kgk5nMvUUrTB1kHNVta4g7dDWhz20fVm=,regex,"(?<SECRET>tkn.v1_[A-Za-z0-9]{71,72}={0,1})"
secrets.services.telegram_bot_token.telegram-bot-token,telegram-bot-token,services,Telegram,WARNING,MEDIUM,regex,telegramvI31075328:UB4SXapQVoa6m2Ntg4tyWQe4idhE073egQH,regex,"(?i:telegram)(?:\R|.){0,40}(?<REGEX>\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b)"
secrets.services.tencentcloud_secret.tencentcloud-secret,tencentcloud-secret,services,Tencent,CRITICAL,MEDIUM,regex,IKIDSR06f9Lnf2LasznwDhgBILofZBaTGOq6,regex,(?<ID>\bIKID[A-Za-z0-9]{32}\b)
secrets.services.testingbot.testingbot,testingbot,services,TestingBot,WARNING,MEDIUM,regex,testingbot255fab36a530901e86266515ccc5d917,regex,"(?i:testingbot|secret)(?:\R|.){0,10}(?<SECRET>\b([0-9a-f]{32})\b)"
secrets.services.thegraphmarket.thegraphmarket,thegraphmarket,services,TheGraphMarket,WARNING,MEDIUM,regex,eyJEJw.eyJ38.uL,regex,(?<REGEX>eyJ[a-zA-Z0-9-_]+\.eyJ[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+)
secrets.services.transferwise.transferwise,transferwise,services,Transferwise,CRITICAL,MEDIUM,regex,tokenfc59313f-c754-dedc-be94-76604b616dbf,regex,"(?i:token|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b)"
secrets.services.twelvedata.twelvedata,twelvedata,services,Twelvedata,WARNING,MEDIUM,regex,key00ee637e37d5a0e4a32bb07bd22de34c,regex,"(?i:twelvedata|key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.twilio-api-key.twilio-api-key,twilio-api-key,services,Twilio,ERROR,MEDIUM,regex,SK8df37a1172e1516f35d10a011bcdb68f,regex,(?<ID>\bSK[0-9a-f]{32}\b)
secrets.services.typeform-oauth.typeform-oauth,typeform-oauth,services,Typeform,WARNING,MEDIUM,regex,"client_secret


n
liroOJcdH4I4y7ztDfizyzmZqYLALgfSVgr1alajPvSV",regex,"(?i:client[-_]?secret)(?:\R|.){0,40}(?<SECRET>\b([0-9A-Za-z]{44})\b)"
secrets.services.ubidots-apikey.ubidots-apikey,ubidots-apikey,services,Ubidots,ERROR,MEDIUM,regex,BBZU-61fbf6f3ec7fb89cb06e76ddf996e398373,regex,(?<REGEX>BB[A-Z]{2}-[0-9a-f]{35})
secrets.services.upstash-redis.upstash-redis,upstash-redis,services,Upstash,ERROR,MEDIUM,regex,"redisP8#8
fBlGW7J5xv43fuKL4jKY099EKu9DvY07PZR4nzo2DPEb4k-Oaa",regex,"(?i:token|redis)(?:\R|.){0,40}(?<TOKEN>\b([A-Za-z0-9_-]{50,70})\b)"
secrets.services.uptimerobot.uptimerobot,uptimerobot,services,UptimeRobot,WARNING,MEDIUM,regex,u22159-e1f6cda0f6830b460936d706,regex,"(?<KEY>(u[0-9]{5,7}-[a-f0-9]{24}))"
secrets.services.userstack.userstack,userstack,services,Userstack,INFO,MEDIUM,regex,key CEme07f99292c0dcea8c56259309bdf0cd4,regex,"(?i:userstack|key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.valtown.valtown,valtown,services,ValTown,WARNING,MEDIUM,regex,vtwn_5fVdnBks8iadTJVEB8YngDM0mTku,regex,(?<REGEX>\bvtwn_[A-Za-z0-9]{28}\b)
secrets.services.vatlayer.vatlayer,vatlayer,services,VATlayer,WARNING,MEDIUM,regex,"key:x

54ec85d75929af107d9dee7d8d497287",regex,"(?i:vatlayer|key)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.vault_service_legacy.vault_service_legacy,vault_service_legacy,services,Vault,CRITICAL,MEDIUM,regex,hashicorps.a7eLkIVl2tLvL8bWkNVTvhzS4ZyfnPeucuvgqS54JwsQbve6cc7pNcz8eU2PBFT098NkbUGH-S4HW0PWrq38MMnFLA,regex,"(?i:vault|hashicorp)(?:\R|.){0,40}(?<REGEX>\b(s\.[a-zA-Z0-9_-]{90,110})\b)"
secrets.services.vercel-ai-gateway.vercel-ai-gateway,vercel-ai-gateway,services,Vercel,ERROR,MEDIUM,regex,vck_TyDC7eNR1fcTT6JYUGHeL4c3tzM0zRj1YIUn5K2yBMFQmQAZIG9xF92C,regex,(?<REGEX>vck_[0-9A-Za-z]{56})
secrets.services.vercel-app-refresh.vercel-app-refresh,vercel-app-refresh,services,Vercel,ERROR,MEDIUM,regex,vcr_IliVf9jhhKXTUo12bOheVO5Wqi5eGRahCTQjjOM6GlU4uXAFKXMbFTfj,regex,(?<REGEX>vcr_[0-9A-Za-z]{56})
secrets.services.vercel-app.vercel-app,vercel-app,services,Vercel,ERROR,MEDIUM,regex,vca_ZifUyarAMQVJYcrMiTy8L7HOigZSoZ5T05GyuG04w4oy4vOcSa03dtPa,regex,(?<REGEX>vca_[0-9A-Za-z]{56})
secrets.services.vercel-blob.vercel-blob,vercel-blob,services,Vercel,ERROR,MEDIUM,regex,vercel_blob_rw_vnGbSK8R9BuhAied_uvBoC4raAatfwILYO8S3lY6ufJ4xB9,regex,(?<KEY>vercel_blob_(r|w|rw)_[A-Za-z0-9]{16}_[A-Za-z0-9]{30})
secrets.services.vercel-integration.vercel-integration,vercel-integration,services,Vercel,ERROR,MEDIUM,regex,vci_dzDpT4nNQv1q1gNayFWQmdcr0c67acUvFZiSo008l8WB0EfVX7ehVGvM,regex,(?<REGEX>vci_[0-9A-Za-z]{56})
secrets.services.verkada.verkada,verkada,services,Verkada,ERROR,MEDIUM,regex,"apikeyE

aGGwnLtJsUSYmSMCIzrl/zIIri2ewdjEih9UpYZMPEn6psu1aSLbgVi4PP7/BIfAk+GuT02qh8CUJvHzK8FnBEtblY7R8kOwTd==",regex,"(?i:api[-_]?key|verkada)(?:\R|.){0,40}(?<REGEX>\b([a-zA-Z0-9+/]{98}==))"
secrets.services.versioneye.versioneye,versioneye,services,Versioneye,WARNING,MEDIUM,regex,"api-keyS
irZvi35MJYNL5hCIKDdWIxm6nhZVWFknWxtl2uR19T",regex,"(?i:versioneye|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-zA-Z0-9]{40})\b)"
secrets.services.voicegain.voicegain,voicegain,services,Voicegain,WARNING,MEDIUM,regex,eyJJ1sqn.eyJNsUJNW.7,regex,(?<REGEX>eyJ[0-9A-Za-z]+\.eyJ[0-9A-Za-z]+\.[A-Za-z0-9_-]+)
secrets.services.vultr.vultr,vultr,services,Vultr,CRITICAL,MEDIUM,regex,"tokene
IFVDCMKTUENS53FWZY8N8DAKJRUR9PIAZG5O",regex,"(?i:vultr|token|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([A-Z0-9]{36})\b)"
secrets.services.weaviate.weaviate,weaviate,services,Weaviate,ERROR,MEDIUM,regex,8yEQvLTxOshZpWfvBLyhhurUoHEuDzVh0UkJfYA6uH0FTKBk4Pq60xMkjGO2OGInpykRl0jN8wprRxbBPV92MjAw,regex,(?<REGEX>\b([A-Za-z0-9]{80}PV92MjAw)\b)
secrets.services.webflow-workspace.webflow-workspace,webflow-workspace,services,Webflow,ERROR,MEDIUM,regex,ws-551022b0fa8d6e2434ebc120f2ad1a7bd7667a4f18c63536edde90304cd03b8c,regex,(?<REGEX>(ws-[a-f0-9]{64}))
secrets.services.webscraper.webscraper,webscraper,services,Webscraper,INFO,MEDIUM,regex,"token


meE64pfOGRhIflm9TC6nuTjETREpc8Jfx2bAv2kFNv1ywwC1vqLiu6a16e61n",regex,"(?i:webscraper|token|api[-_]?key)(?:\R|.){0,40}(?<REGEX>\b([a-zA-Z0-9]{60})\b)"
secrets.services.wepay.wepay,wepay,services,WePay,CRITICAL,MEDIUM,regex,stage_ZooLRECGpopAuZekSFtiAlzJJZ2qVlJk01IUksarQoOZz91UhFaI,regex,"(?<KEY>\b((stage|production)_[a-zA-Z0-9]{52,56})\b)"
secrets.services.whoxy.whoxy,whoxy,services,Whoxy,INFO,MEDIUM,regex,"whoxy

Yw0q4sbw5a2hjw097mf4y91otr5prtz0lv",regex,"(?i:whoxy|key)(?:\R|.){0,40}(?<REGEX>\b([0-9a-z]{33})\b)"
secrets.services.woocommerce.woocommerce,woocommerce,services,WooCommerce,ERROR,MEDIUM,regex,cs_fb6b5b06e5a465e5eb0841919709fdfa4decdfc4,regex,(?<SECRET>(cs_[a-f0-9]{40}))
secrets.services.wordboundary.huggingface.huggingface,huggingface,services,Huggingface,CRITICAL,MEDIUM,regex,%20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,regex,(\\(n|f|t)|%20)(?<REGEX>hf_[a-zA-Z]{34})
secrets.services.worldcoinindex.worldcoinindex,worldcoinindex,services,WorldCoinIndex,INFO,MEDIUM,regex,"keyn

eKtb2A9X5Rtnn1qa2UgbWmS1u4k2vruAl4f",regex,"(?i:worldcoinindex|key)(?:\R|.){0,40}(?<REGEX>\b([a-zA-Z0-9]{35})\b)"
secrets.services.xendit.xendit,xendit,services,Xendit,CRITICAL,MEDIUM,regex,xnd_production_W1S6xKAm4VIrqATb29zGf6IsuNjjYTJVcG0PJymsH405c5MwcWfAbFSE8,regex,"(?<REGEX>xnd_(development|production)_[A-Za-z0-9]{57,64})"
secrets.services.yandex-aws-token.yandex-aws-token,yandex-aws-token,services,Yandex,ERROR,HIGH,regex,yandex	b'|?===YCpKhC9sHzHGJpYbWiwCkn4uLA7e8NolFMRGsCrQ,regex,"(?i)(?:yandex)(?:[0-9a-z\-_\t.]{0,20})(?:[\s|']|[\s|""]){0,3}(?:=|>|:{1,3}=|\|\|:|<=|=>|:|\?=)(?:'|\""|\s|=|\x60){0,5}((?<REGEX>YC[a-zA-Z0-9_\-]{38}))(?:['|\""|\n|\r|\s|\x60|;]|$)"
secrets.services.yookassa-sandbox.yookassa-sandbox,yookassa-sandbox,services,Yookassa,INFO,MEDIUM,regex,test_QDX3aw8VETJasbfKzb3mk6Nu4iyUOBppSQg3ioKmjNF,regex,(?<KEY>test_[A-Za-z0-9_]{43})
secrets.services.yookassa.yookassa,yookassa,services,Yookassa,CRITICAL,MEDIUM,regex,live_j5qLoihZoKnYtTb0CVmfI_N7YT1w81oxQnk9vnnEfmx,regex,(?<KEY>live_[A-Za-z0-9_]{43})
secrets.services.zegocloud.zegocloud,zegocloud,services,ZegoCloud,ERROR,MEDIUM,regex,secretE+^S7aa3d626a295cc242be48e1c34c34b8f,regex,"(?i:secret)(?:\R|.){0,40}(?<REGEX>\b([a-f0-9]{32})\b)"
secrets.services.zenhub.zenhub,zenhub,services,ZenHub,WARNING,MEDIUM,regex,zh_7f850c651d8fb623c863ce2bf37c0b97a041caefc8887419bad54f94685859e4,regex,(?<REGEX>\b(zh_[a-f0-9]{64})\b)
secrets.services.zerotier.zerotier,zerotier,services,ZeroTier,ERROR,MEDIUM,regex,"tokenZ
qd5016mjUzCzwfC5CVdyZRMRpMPAUYlS",regex,"(?i:zerotier|token)(?:\R|.){0,40}(?<REGEX>\b([0-9a-zA-Z]{32})\b)"
secrets.services.zipbooks-token.zipbooks-token,zipbooks-token,services,Zipbooks,WARNING,MEDIUM,regex,eyJjV.0_my.WpyR_,regex,(?<REGEX>\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+\b)
secrets.services.zipbooks.zipbooks,zipbooks,services,Zipbooks,WARNING,MEDIUM,regex,"password,r
z
gt3nLe?Y&",regex,"(?i:password)(?:\R|.){0,10}(?<PASS>.{8,}\b)"
intel_devsecops.custom.secrets.generic_password,generic_password,custom,Generic,ERROR,MEDIUM,regex,"password = ""P@ssw0rd123!""",manual,"(?i)(?<PASS_KEYWORD>password|pwd|passwd)(?:\s|:\s*\w+)?\s*(?:(?:[""']\s*[\]\)])|[""']|\])?\s*(?:=|:=|\|\|:|<=|=>|:|\?=)\s*(?:f)?(?<PASS_QUOTED>(?<QUOTE>(?:'''|""""""|\\?['""`]))(?<PASS>(?:(?:\\.)|(?!\k<QUOTE>).){4,256})\k<QUOTE>)(?![a-zA-Z_\d]);?"
intel_devsecops.custom.secrets.intel.geti_pat,geti_pat,custom,Generic,ERROR,MEDIUM,regex,GETI_PAT=abc123def456ghi789jkl012mno345pqr678stu901vwx234yz,manual,(?<REGEX>\b(geti_pat_[0-9A-Za-z]{43}_[0-9A-Za-z]{6})\b)
intel_devsecops.custom.secrets.intel.sign_tool_credential,sign_tool_credential,custom,Generic,ERROR,MEDIUM,regex,"signtool.exe sign -u ""corp\svcuser"" -p ""SignP@ss2024!"" mypkg.exe",manual,"(?i)(((code)_?sign)|(sign_?(file|tool|command|cmd|client))|(sign\w+\.(sh|exe)))(?-i)(.*?)-u(\s+|=)(?<quote1>\\?['""]?)(?<domain>[a-zA-Z]{3,4}\\?\\)?(?<USER>[a-zA-Z0-9\-_]{5,20})\k<quote1>(.*)-p(\s+|=)(?<PASS_QUOTED>(?<quote>\\?['""]?)(?<PASS>[a-zA-Z0-9~!@\$%\^&\*_\-\+=`\|\\\(\)\{\}\[\]:;""'<>,\.\?\/\#]{7,256})\k<quote>)"
