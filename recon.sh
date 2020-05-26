#!/bin/bash
 
url=$1
 
if [ ! -d "$url" ]; then
        mkdir  $url
fi
 
if [ ! -d "$url/recon" ]; then
        mkdir $url/recon
fi
if [ ! -d "$url/recon/httprobe" ];then
        mkdir $url/recon/httprobe
fi

if [ ! -d "$url/recon/3level" ]; then
	mkdir $url/recon/3level

fi
if [ ! -d "$url/recon/potential_takeovers" ];then
        mkdir $url/recon/potential_takeovers
fi

echo "[+] Harvesting Subdomains with Sublist3r..."
python ~/tools/Sublist3r/sublist3r.py -d $url -p 80.443 >> $url/recon/sublist3r.txt
cat $url/recon/sublist3r.txt | grep $1 >> $url/recon/final.txt
rm $url/recon/sublist3r.txt

echo "[+] Harvesting Subdomains with Assetfinder..."

assetfinder --subs-only $url >> $url/recon/assets.txt
cat $url/recon/assets.txt | grep $1  >> $url/recon/final.txt
rm $url/recon/assets.txt

echo "[+] Harvesting Subdomains with Amass..."
amass enum -brute -min-for-recursive 3 -d $url >> $url/recon/f.txt
sort -u $url/recon/f.txt >> $url/recon/final.txt
rm $url/recon/f.txt

echo "[+] Probing for alive domains..."
cat $url/recon/final.txt | sort -u | httprobe -s -p https:443 | sed 's/https\?:\/\///' | tr -d ':443' | sort -u >> $url/recon/httprobe/alive.txt
sort -u $url/

echo "[+] Compiling third-level domains..."
cat ~/$url/recon/httprobe/alive.txt | grep -Po "(\w+\.\w+\.\w+)$" | sort -u >> $url/recon/third-level.txt
for line in $(cat $url/recon/third-level.txt);do echo $line | sort -u | tee -a $url/recon/final.txt;done


#echo "[+] Bruteforcing 3rd Level subdomains with Dirsearch..."
for domain in $(cat $url/recon/third-level.txt);do python3 ~/tools/dirsearch/dirsearch.py -u $domain -E >> $url/recon/3level/$domain.txt;done



echo "[+] Checking for possible subdomain takeover..."
if [ ! -f "$url/recon/potential_takeovers/domains.txt" ];then
    touch $url/recon/potential_takeovers/domains.txt
fi

if [ ! -f "$url/recon/potential_takeovers/potential_takeovers1.txt" ];then
    touch $url/recon/potential_takeovers/potential_takeovers1.txt
fi
for line in $(cat ~/$url/recon/final.txt);do echo $line |sort -u >> ~/$url/recon/potential_takeovers/domains.txt;done
subjack -w $url/recon/httprobe/alive.txt -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 >> $url/recon/potential_takeovers/potential_takeovers/potential_takeovers1.txt
sort -u $url/recon/potential_takeovers/potential_takeovers1.txt >> $url/recon/potential_takeovers/potential_takeovers.txt
rm $url/recon/potential_takeovers/potential_takeovers1.txt
