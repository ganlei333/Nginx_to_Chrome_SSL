#!/bin/bash
#Centos7 下测试通过
base=/usr/local/src
echo ###Install EnviroMment###
yum -y install epel-release
yum -y install pcre-devel wget openssl-devel gcc make libxslt-devel libxml2-devel gd-devel lua-devel GeoIP-devel libjemalloc-devel http-tools jemalloc-devel git tar
cd $base
echo ##Install Openssl##
wget https://www.openssl.org/source/old/1.1.0/openssl-1.1.0l.tar.gz
tar -zxvf openssl-1.1.0l.tar.gz
cd openssl-1.1.0l/
./config --prefix=/usr/local/openssl --openssldir=/etc/ssl --libdir=lib shared zlib-dynamic
make install
echo /usr/local/openssl/lib/ >> /etc/ld.so.conf
ldconfig  -v
export PKG_CONFIG_PATH=/usr/local/openssl/lib/pkgconfig
export LD_LIBRARY_PATH=/usr/local/openssl/lib
cd $base
echo ###Install tengine###
wget http://tengine.taobao.org/download/tengine-2.3.2.tar.gz
tar -zxvf tengine-2.3.2.tar.gz 
cd tengine-2.3.2
sed -i  's/$OPENSSL\/.openssl/$OPENSSL/g'  auto/lib/openssl/conf
cd $base
git clone https://github.com/vozlt/nginx-module-vts.git
cd tengine-2.3.2
./configure --prefix=/usr/local/nginx --with-http_realip_module --with-http_v2_module --with-jemalloc --with-openssl=/usr/local/openssl/ --add-module=../nginx-module-vts/ --add-module=./modules/ngx_http_upstream_vnswrr_module/ --add-module=./modules/mod_config/ --add-module=./modules/ngx_backtrace_module/ --add-module=./modules/ngx_http_concat_module/ --add-module=./modules/ngx_http_footer_filter_module/ --add-module=./modules/ngx_http_proxy_connect_module/ --add-module=./modules/ngx_http_reqstat_module/ --add-module=./modules/ngx_http_slice_module/ --add-module=./modules/ngx_http_sysguard_module/ --add-module=./modules/ngx_http_trim_filter_module/ --add-module=./modules/ngx_http_upstream_check_module/ --add-module=./modules/ngx_http_upstream_consistent_hash_module/ --add-module=./modules/ngx_http_upstream_dynamic_module/ --add-module=./modules/ngx_http_upstream_dyups_module/  --add-module=./modules/ngx_http_upstream_session_sticky_module/ --add-module=./modules/ngx_http_user_agent_module/ --add-module=./modules/ngx_multi_upstream_module/ --add-module=./modules/ngx_slab_stat/
make -j 48
make install
echo ##同步配置文件##
mv /usr/local/nginx/conf/nginx.conf  /usr/local/nginx/conf/nginx.conf.bak
#生成Nginx主配置文件
cat > /usr/local/nginx/conf/nginx.conf <<EOF
user  nobody nobody; # 出于安全，无特别要求禁止使用root

worker_processes  auto; # 推荐配置为CPU核数
worker_cpu_affinity auto;

error_log  logs/error.log  error;
pid        logs/nginx.pid; # 此路径不建议更改

worker_rlimit_nofile 1048576;
 
events {
    use epoll;
    multi_accept on;
    worker_connections  87381;
}

 
http {
    include       mime.types;
    default_type  text/plain;

    log_format  main '\$proxy_add_x_forwarded_for $remote_addr - [\$time_local] "\$request" '
                         '\$status \$body_bytes_sent '
                         '"\$request_time" "\$upstream_response_time" "\$upstream_addr" "\$request_body "';

    log_format  proxy_protocol '\$proxy_add_x_forwarded_for $remote_addr - [\$time_local] "\$request" '
                         '\$status $body_bytes_sent '
                         '"\$request_time" "\$upstream_response_time" "\$upstream_addr" "\$proxy_protocol_addr"';
	
    sendfile    on;
    tcp_nopush  on;
    tcp_nodelay on;
	
    server_tokens off; # 关闭版本号显示
    keepalive_timeout  120;
    server_names_hash_bucket_size 512;
     
    #fastcgi_connect_timeout 300s;
    #fastcgi_send_timeout 300s;
    #fastcgi_read_timeout 300s;
    #fastcgi_buffer_size 128k;
    #fastcgi_buffers 8 128k;
    #fastcgi_busy_buffers_size 256k;
    #fastcgi_temp_file_write_size 256k;
     
    variables_hash_max_size  1024;
    set_real_ip_from 10.0.0.0/8;
    set_real_ip_from 172.28.0.0/16;
    set_real_ip_from 192.168.0.0/16;
    real_ip_header X-Forwarded-For;
     
    gzip on;
    gzip_min_length 32k;
    gzip_buffers 16 64k;
    gzip_http_version 1.1;
    gzip_comp_level 6;
    gzip_types text/plain application/json application/x-javascript text/css application/xml;
    gzip_vary on;
    
    vhost_traffic_status_zone; 
    client_max_body_size 100m;
#############################################################################################
    include conf.d/default.conf;
    #include conf.d/weihu.conf; #维护时候，注释上面一条和下面一条记录，开启本条记录
    include vhost.d/*.conf; # 表示Nginx会继续读取并解析/usr/local/nginx/conf/vhost.d/*.conf中的配置文件

}

EOF

mkdir /usr/local/nginx/conf/conf.d/ -p
#生成默认站点配置文件
cat > /usr/local/nginx/conf/conf.d/default.conf <<EOF
server {
    listen 80;
    server_name _;
    root html;
    index index.html index.htm;
    access_log /data/nginx_logs/access_nginx.log;
    
    location /nginx_status {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }   
    location /jddvts {
        auth_basic "Restricted";
        auth_basic_user_file nginx.auth;
        vhost_traffic_status_display;
        vhost_traffic_status_display_format html;
        access_log off;
    }   
    location /status {
        check_status;
        access_log   off;
        allow 127.0.0.1;
        allow 192.168.5.0/24;
        #deny all;
    }   
    
    location ~ .*\.(gif|jpg|jpeg|png|bmp|swf|flv|mp4|ico)$ {
        expires 30d;
        access_log off;
    }   
    location ~ .*\.(js|css)?$ {
        expires 7d;
        access_log off;
    }   
    location ~ /\.ht {
      deny all;
    } 
} 


EOF


mkdir /usr/local/nginx/conf/vhost.d/ -p
#生成站点配置文件
cat > /usr/local/nginx/conf/vhost.d/test.jddops.com.conf <<EOF
server {
    listen               443 ssl;  #监听在443端口
    server_name          test.jddops.com; #服务域名
    ssi on;
    ssi_silent_errors on;
    ssi_types text/shtml;
    ssl_certificate      /usr/local/nginx/conf/test.jddops.com.pem;  #服务器证书
    ssl_certificate_key  /usr/local/nginx/conf/test.jddops.com.key; #服务器证书私钥
    ssl_client_certificate /usr/local/nginx/conf/ca.pem;     #客户端证书的CA证书
    #ssl_crl /usr/local/nginx/conf/ca.crl;
    ssl_session_timeout  5m;  #连接超时时间
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
    ssl_ciphers ECDHE-RSA-AES256-SHA384:AES256-SHA256:RC4:HIGH:!MD5:!aNULL:!eNULL:!NULL:!DH:!EDH:!AESGCM;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_verify_client              on;
    ssl_verify_depth 2;
    add_header                     X-Client-Certificate-Status \$ssl_client_verify;
    index index.html;
    root /usr/local/nginx/html/;

    access_log /data/nginx_logs/test.jddops.com.access.log;
    error_log /data/nginx_logs/test.jddops.com.error.log;
}


EOF

#生成Nginx服务配置文件
cat > /usr/lib/systemd/system/nginx.service <<EOF
[Unit]
Description=nginx - high performance web server
Documentation=http://nginx.org/en/docs/
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/usr/local/nginx/logs/nginx.pid
ExecStartPre=/usr/local/nginx/sbin/nginx -t -c /usr/local/nginx/conf/nginx.conf
ExecStart=/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf
ExecReload=/bin/kill -s HUP $MAINPID
ExecStop=/bin/kill -s QUIT $MAINPID
PrivateTmp=true

[Install]
WantedBy=multi-user.target


EOF

#生成vts登录账号密码文件
#也可以用 #printf "vtsadmin:$(openssl passwd -l Pass123\n)" >> /usr/local/nginx/conf/nginx.auth
cat > /usr/local/nginx/conf/nginx.auth <<EOF
vtsadmin:kNoITqNyYrPV.
EOF

#生成站点证书密钥
cat > /usr/local/nginx/conf/test.jddops.com.key <<EOF
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIA5c2K/FuNLdAIKUjihaJGhwlPXcmq3S9Esb+EB0BTkFoAoGCCqGSM49
AwEHoUQDQgAEy3trsw9NhswusFPNvIglEeE7Bd2/Kk1DBSGZdmzPvqMZ+Hi1+CNm
GAwrlkxbsxvulFJJmk3AJU4JRFhoBfPaNw==
-----END EC PRIVATE KEY-----

EOF

#生成站点证书
cat > /usr/local/nginx/conf/test.jddops.com.pem <<EOF
-----BEGIN CERTIFICATE-----
MIIC/jCCAqSgAwIBAgIRAMmNYVH6u/QjBPh4JOiJfzQwCgYIKoZIzj0EAwIwgaEx
CzAJBgNVBAYTAkNOMQ8wDQYDVQQIEwZTdVpob3UxETAPBgNVBAcTCEtlSmlZdWFu
MSwwCwYDVQQJEwRkZW1vMA0GA1UECRMGc3RyZWV0MA4GA1UECRMHYWRkcmVzczEP
MA0GA1UEERMGMjE1MjAwMQwwCgYDVQQKEwNKREQxDDAKBgNVBAsTA09QUzETMBEG
A1UEAxMKamRkb3BzLmNvbTAeFw0yMTA2MDgwMjU0MzlaFw0zMTA2MDYwMjU0Mzla
MIGjMQswCQYDVQQGEwJDTjEPMA0GA1UECBMGU3VaaG91MREwDwYDVQQHEwhLZUpp
WXVhbjEsMAsGA1UECRMEZGVtbzANBgNVBAkTBnN0cmVldDAOBgNVBAkTB2FkZHJl
c3MxDzANBgNVBBETBjIxNTIwMDEMMAoGA1UEChMDSkREMQwwCgYDVQQLEwNPUFMx
FTATBgNVBAMMDCouamRkb3BzLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA
BMt7a7MPTYbMLrBTzbyIJRHhOwXdvypNQwUhmXZsz76jGfh4tfgjZhgMK5ZMW7Mb
7pRSSZpNwCVOCURYaAXz2jejgbgwgbUwDgYDVR0PAQH/BAQDAgGmMBMGA1UdJQQM
MAoGCCsGAQUFBwMBMAwGA1UdEwEB/wQCMAAwKQYDVR0OBCIEIA659CiPOy6DEjrj
yOw7+VAxWsNK9cMYJOTVAMN7kbxHMCsGA1UdIwQkMCKAIBvQWzVq5RM0cURLL5lp
2BaS5Rc+Fy3z7k/IQ6Rx0AWHMCgGA1UdEQQhMB+CCWxvY2FsaG9zdIIMKi5qZGRv
cHMuY29thwR/AAABMAoGCCqGSM49BAMCA0gAMEUCIQD7o463Ulaps3c7TdNc6I0F
WKSM5bwfDn+sRDM0Tf0BnAIgaEB7S4byOl3WMpCV3RcrD6EllcABT4R4+w6xSM2i
L1g=
-----END CERTIFICATE-----

EOF

# 生成CA根证书
cat > /usr/local/nginx/conf/ca.pem <<EOF
-----BEGIN CERTIFICATE-----
MIIC3TCCAoKgAwIBAgIRAPip6j171/cW5uxi5/cYWTUwCgYIKoZIzj0EAwIwgaEx
CzAJBgNVBAYTAkNOMQ8wDQYDVQQIEwZTdVpob3UxETAPBgNVBAcTCEtlSmlZdWFu
MSwwCwYDVQQJEwRkZW1vMA0GA1UECRMGc3RyZWV0MA4GA1UECRMHYWRkcmVzczEP
MA0GA1UEERMGMjE1MjAwMQwwCgYDVQQKEwNKREQxDDAKBgNVBAsTA09QUzETMBEG
A1UEAxMKamRkb3BzLmNvbTAeFw0yMTA2MDgwMjU0MjlaFw0zMTA2MDYwMjU0Mjla
MIGhMQswCQYDVQQGEwJDTjEPMA0GA1UECBMGU3VaaG91MREwDwYDVQQHEwhLZUpp
WXVhbjEsMAsGA1UECRMEZGVtbzANBgNVBAkTBnN0cmVldDAOBgNVBAkTB2FkZHJl
c3MxDzANBgNVBBETBjIxNTIwMDEMMAoGA1UEChMDSkREMQwwCgYDVQQLEwNPUFMx
EzARBgNVBAMTCmpkZG9wcy5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASK
4/mRPj0tOyztBVN/lL2e8kyFmYuj99Q3quFlJcKkV7HTeRJYml3BCB9syb/xaTFb
N9QCvlut2fFMq2uKtj/1o4GYMIGVMA4GA1UdDwEB/wQEAwIBpjAdBgNVHSUEFjAU
BggrBgEFBQcDAgYIKwYBBQUHAwEwDwYDVR0TAQH/BAUwAwEB/zApBgNVHQ4EIgQg
G9BbNWrlEzRxREsvmWnYFpLlFz4XLfPuT8hDpHHQBYcwKAYDVR0RBCEwH4IJbG9j
YWxob3N0ggwqLmpkZG9wcy5jb22HBH8AAAEwCgYIKoZIzj0EAwIDSQAwRgIhAIA2
fr5d063Z+zJTAMO0deJTT0rappzZvI2tlta8y2FFAiEA8IUd2uA/pe8LGhkQFY7U
odPHpWhBlrLu3+s3EiCQqvM=
-----END CERTIFICATE-----

EOF

mkdir -p /data/nginx_logs/
echo #启动tengine#
systemctl start nginx
