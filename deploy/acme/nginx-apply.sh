#!/bin/sh
# AWAI-465: the only root action the receiver may take, through sudoers:
#   yataverse-acme-recv ALL=(root) NOPASSWD: /usr/local/libexec/yataverse-acme/nginx-apply.sh ""
# No arguments are accepted. Test the full configuration, then reload.
set -eu
[ "$#" = 0 ] || exit 2
/usr/sbin/nginx -t -q
/usr/bin/systemctl reload nginx
