#!/bin/bash

curl --retry 5 --retry-delay 2 --max-time 20 -L -O https://github.com/Delta-Kronecker/IP-Bypass-Plus-Frag/releases/latest/download/ip-bypass-plus-frag-termux.tar.gz

if [ $? -ne 0 ]; then
    echo "Download failed"
    exit 1
fi

mkdir -p ip-bypass-plus-frag && tar -xzf ip-bypass-plus-frag-termux.tar.gz -C ip-bypass-plus-frag && rm ip-bypass-plus-frag-termux.tar.gz

if [ $? -ne 0 ]; then
    echo "Extraction failed"
    exit 1
fi

chmod +x ip-bypass-plus-frag/ip-bypass-plus-frag

if [ -n "$ZSH_VERSION" ]; then
    SHELL_RC="$HOME/.zshrc"
else
    SHELL_RC="$HOME/.bashrc"
fi

if ! grep -q "alias i='~/ip-bypass-plus-frag/ip-bypass-plus-frag'" "$SHELL_RC" 2>/dev/null; then
    echo "alias i='~/ip-bypass-plus-frag/ip-bypass-plus-frag'" >> "$SHELL_RC"
    echo "Alias added to $SHELL_RC"
else
    echo "Alias already exists in $SHELL_RC"
fi

echo "Installation complete! Run 'source $SHELL_RC' or restart terminal to use 'i' command."
