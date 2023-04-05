#!/bin/bash
echo "Content-type: text/html"
echo ""

# Get address from get param "addr"
addr=$(echo "$QUERY_STRING" | sed -n 's/^.*addr=\([^&]*\).*$/\1/p' | sed "s/%20/ /g")

nmap="$(nmap $addr)"
# Split $nmap results by lines
readarray -t nmap_lines <<< "$nmap"

# If the address contains a parenthesis
if [[ ${nmap_lines[1]} == *"("* ]]; then
    ip=$(echo ${nmap_lines[1]} | sed -E 's/.*(\(.*\))/\1/g') # Find ip address within parentheses
    ip="${ip:1:${#ip}-2}" # Trim leading and trailing parentheses
else
    ip=$addr
fi

ipgeolocation_apikey="$(cat ipgeolocation_apikey.txt)" # Keep the api key secret from github viewers
geo_json=$(curl -s "https://api.ipgeolocation.io/ipgeo?apiKey=$ipgeolocation_apikey&ip=$ip")

country_code="$(echo $geo_json | jq -r '.country_code2' | tr '[:upper:]' '[:lower:]')"
country_name="$(echo $geo_json | jq -r '.country_name')"



echo "<!DOCTYPE html>"
echo "<html lang=\"en\">"
echo "<head>"
echo "    <meta charset=\"UTF-8\">"
echo "<title>Probing: $addr</title>"
echo "</head>"
echo "<body>"
echo "<h2>Probing:</h2>"
echo "<div style=\"margin-left: 50px\">"
echo "<div style=\"display: flex; text-align:center; font-size: 1.25em\">"
echo "<img src=\"http://$addr/favicon.ico\" height=\"25px\" style=\"margin-right: 10px\"/>"

# If an IP address is present in paraenthesis, display it with the address from the GET param
if [[ ${nmap_lines[1]} == *"("* ]]; then
    echo "$addr $(echo ${nmap_lines[1]} | sed -E 's/.*(\(.*\))/\1/g')" 
else
    echo "$addr" 
fi

echo "<img src=\"https://flagcdn.com/48x36/$country_code.png\" height=\"25px\" style=\"margin-left: 10px\" title=\"$country_name\">"

echo "</div></div>"
echo "<div style=\"display: flex;\"><div>"
echo "<h2>Ports:</h2>"
echo "<div style=\"margin-left: 50px\">"

# Slice nmap_lines from line 6 to seconds-to-last, [6:-2]
ports=("${nmap_lines[@]:6}")
unset 'ports[-1]'
unset 'ports[-1]'

#echo "${ports[@]}"

echo "<table><tr><th>Port</th><th>State</th><th>Service</th></tr>"

for i in "${ports[@]}"; do 
    for col in $i; do
        echo "<td>$col</td>"
    done
    echo "</tr>"
done

echo "</table>"
for i in "${nmap_lines[@]}"; do 
    if echo "$i" | grep -q "^Not shown"; then
        echo "<small>$i)</small>"
    fi
done
echo "</div></div>"




traceroute="$(traceroute $addr)"
# Split $traceroute results by lines
readarray -t traceroute_lines <<< "$traceroute"


echo "<div style=\"margin-left: 50px\">"
echo "<h2>Traceroute:</h2>"
echo "<div style=\"margin-left: 20px\">$(echo ${traceroute_lines[0]} | sed 's/\([^,]*\), \(.*\)/\2/')</div>"
echo "<div style=\"margin-left: 20px\"><ul style=\"list-style: none;\">"

for line in "${traceroute_lines[@]:1}"; do
    # Find the first ip address on each line
    line_ip=$(echo $line | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1) 

    line_geo_json=$(curl -s "https://api.ipgeolocation.io/ipgeo?apiKey=$ipgeolocation_apikey&ip=$line_ip")

    line_country_code="$(echo $line_geo_json | jq -r '.country_code2' | tr '[:upper:]' '[:lower:]')"
    line_country_name="$(echo $line_geo_json | jq -r '.country_name')"

    echo "<li class=\"traceroute_list_item\">"
    
    if [[ $line =~ [0-9]+" "" "\*" "\*" " ]]; then # For some reason, neither \s nor [:space:] match spaces, only " " ...
        echo "<span style=\"margin-right: 35px; margin-left: 10px; font-weight: bold; font-size: 1.5em\" title=\"ICMP packets are likely blocked by the firewall asscoiated with this node\">!</span>"
    elif [[ "$line_country_name" != "null" ]]; then
        echo "<img src=\"https://flagcdn.com/48x36/$line_country_code.png\" height=\"25px\" style=\"margin-right: 20px\" title=\"$line_country_name\">"
    else
        echo "<span style=\"margin-right: 35px; margin-left: 10px; font-weight: bold; font-size: 1.5em\" title=\"No geolocation available\">?</span>"
    fi
    echo "$line</li>"

    sleep 0.02 # Sleep to avoid API rate limiting 

done

echo "</ul>"
echo "</div></div></div>"


echo "<style>"
cat ../html/stylesheet.css
echo "</style>"

echo '</body></html>'
exit 0
