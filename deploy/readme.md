### Generate RSA keys in `keys` folder

```shell
openssl genrsa -out access_private.pem 4096 && \
openssl rsa -in access_private.pem -pubout -out access_public.pem && \
openssl genrsa -out refresh_private.pem 4096 && \
openssl rsa -in refresh_private.pem -pubout -out refresh_public.pem
```

### Init tables with `init.sql` file

...

### Run it