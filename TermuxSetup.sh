#!/bin/bash

curl --retry 5 --retry-delay 2 --max-time 20 -L -O https://github.com/Delta-Kronecker/IP-Bypass-Plus-Frag/releases/download/0.1.0/ip-bypass-plus-frag-termux.tar.gz

if [ $? -ne 0 ]; then
    exit 1
fi

mkdir -p ip-bypass-plus-frag && tar -xzf ip-bypass-plus-frag-termux.tar.gz -C ip-bypass-plus-frag && rm ip-bypass-plus-frag-termux.tar.gz

if [ $? -ne 0 ]; then
    exit 1
fi

chmod +x ip-bypass-plus-frag/ip-bypass-plus-frag

if [ -n "$ZSH_VERSION" ]; then
    SHELL_RC="$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ]; then
    SHELL_RC="$HOME/.bashrc"
else
    SHELL_RC="$HOME/.bashrc"
fi

echo "alias i='~/ip-bypass-plus-frag/ip-bypass-plus-frag'" >> "$SHELL_RC"

source "$SHELL_RC" 2>/dev/null

exec "$SHELL"
