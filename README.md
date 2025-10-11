# MIN

Absolutely free and open-source messenger, you can host yourself.  
(or just use it here: https://msg-min.xyz)

## About repo

This repo is server only. You can find client here: https://github.com/gooseDes/min-frontend  
Things used:

-   `MariaDB` as database
-   `TypeScript` and `JavaScript` as programming languages

## Settings

### .env configuration (_italian_ means not required):

-   **`EMAIL`** is your email requested by web-push
-   **`VAPID_PUBLIC`** is your own VAPID public key(you can generate it by running `gen_push_keys.js`)
-   **`VAPID_PRIVATE`** is your own VAPID private key
-   **`METERED_SECRET`** is your own secret key on metered.ca
-   **`METERED_DOMAIN`** is your own pre domain on metered. For example: `min.metered.live`. Enter only first part
-   _`JWT_SECRET`_ is like a key for generating and validating tokens
-   _`DB_HOST`_ is an address, the database is running on
-   _`PORT`_ is a port, the server is running on
