#!/bin/bash

if [[ $1 == "up" ]]
then
    mkdir ~/.ssh 2>/dev/null
    [[ ! -f ~/.ssh/trevorproxy ]] && ssh-keygen -t ed25519 -f ~/.ssh/trevorproxy -C trevorproxy -N ""
    public_key=$(cat ~/.ssh/trevorproxy.pub)

    terraform -chdir=infra init
    terraform -chdir=infra apply -auto-approve -var "public_key=$public_key"
elif [[ $1 == "down" ]]
then
    terraform -chdir=infra init
    terraform -chdir=infra destroy -auto-approve -var "public_key="
else
    echo "USAGE: $0 [up | down]"
fi

