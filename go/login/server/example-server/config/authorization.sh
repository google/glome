#!/bin/sh

if [ "$ACTION" != "shell/root" ] && [ "$ACTION" != "reboot" ] && [ "$ACTION" != "" ]
then
  echo "Unauthorized action '$ACTION'" >&2
  exit 1
fi

if [ "$USER" = "admin" ]
then
  exit 0
fi

if [ "$USER" = "default-user"]
then
  if [ "$HOSTIDTYPE" = "hostname" ] && [ "$HOSTID" = "my-server.local" ]
  then
    exit 0
  fi
  if [ "$HOSTIDTYPE" = "serial-number" ] && [ "$HOSTID" = "1234567890" ]
  then
    exit 0
  fi
fi

echo "Not authorized: USER='$USER' HOSTIDTYPE:'$HOSTIDTYPE' HOSTID='$HOSTID' ACTION='$ACTION'" >&2
exit 1
