FROM scratch
COPY . / 
COPY ./etc/config/network.bak /etc/config/network
COPY ./etc/dnsmasq.conf.bak /etc/dnsmasq.conf
RUN mkdir -p /var/lib/misc
COPY ./dnsmasq.leases /var/lib/misc/
CMD /usr/sbin/dnsmasq --no-daemon -k
