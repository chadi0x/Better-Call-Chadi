#!/bin/bash
# Linux Triage Script for Better Call Chadi
# Collects Processes, Network, and Basic Config

OUTFILE="triage_data.txt"

echo "[START] Linux Triage" > $OUTFILE
date >> $OUTFILE
uname -a >> $OUTFILE
whoami >> $OUTFILE

echo "" >> $OUTFILE
echo "[PROCESS LIST]" >> $OUTFILE
ps auxwww >> $OUTFILE

echo "" >> $OUTFILE
echo "[NETWORK CONNECTIONS]" >> $OUTFILE
netstat -antup >> $OUTFILE

echo "" >> $OUTFILE
echo "[OPEN FILES (LSOF)]" >> $OUTFILE
lsof -i -n -P >> $OUTFILE

echo "" >> $OUTFILE
echo "[USER HISTORY]" >> $OUTFILE
cat ~/.bash_history | tail -n 50 >> $OUTFILE

echo "" >> $OUTFILE
echo "[CRON JOBS]" >> $OUTFILE
crontab -l >> $OUTFILE
ls -la /etc/cron* >> $OUTFILE

echo "[END]" >> $OUTFILE

echo "Triage Complete. Upload $OUTFILE to the Dashboard."
