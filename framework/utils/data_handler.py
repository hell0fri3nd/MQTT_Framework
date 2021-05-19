def nmap_shodan_data_merger(ipaddr, ndata, sdata):
    ip = str(ipaddr)

    shod_mqtt_data = []

    # Filter mqtt ports only
    for elem in sdata.get('data'):
        if elem.get('_shodan').get('module') == 'mqtt' or elem.get('_shodan').get('module') == 'secure-mqtt':
            shod_mqtt_data.append(elem)

    # Filter ports object
    port_objs = []
    _n_datalist = ndata.get('scan').get(ip).get('tcp')
    for p_num in _n_datalist:
        for d in shod_mqtt_data:
            # Equal port number and equal service running
            # (sometimes on shodan port 8883 is used as https server)
            if p_num == d.get('port') and _n_datalist.get(p_num).get('name') == d.get('_shodan').get('module'):
                scripts = _n_datalist.get(p_num).get('script')

                obj = {
                    'port': p_num,
                    'state': _n_datalist.get(p_num).get('state'),
                    'reason': _n_datalist.get(p_num).get('reason'),
                    'name': _n_datalist.get(p_num).get('name'),
                    'additional': {
                        'isp': d.get('isp'),
                        'org': d.get('org'),
                        'location': d.get('location'),
                        'hostnames': d.get('hostnames'),
                        'product': _n_datalist.get(p_num).get('product'),
                        'version': _n_datalist.get(p_num).get('version'),
                        'extrainfo': _n_datalist.get(p_num).get('extrainfo'),
                    },
                    'mqtt_code': d.get('mqtt').get('code'),
                    'messages': d.get('mqtt').get('messages'),
                    'script': scripts,
                    'data': d.get('data')
                }

                port_objs.append(obj)

    new_data = {
        'nmap_command': ndata.get('nmap').get('command_line'),
        'ip': ip,
        'hostnames': ndata.get('scan').get(ip).get('hostnames'),
        'uptime': ndata.get('scan').get(ip).get('uptime'),
        'mqtt_ports': port_objs,
        'ports': sdata.get('ports'),
        'osmatch': ndata.get('scan').get(ip).get('osmatch'),
        'location': {
            'city': sdata.get('city'),
            'postal_code': sdata.get('postal_code'),
            'region_code': sdata.get('region_code'),
            'country_name': sdata.get('country_name'),
            'latitude': sdata.get('latitude'),
            'longitude': sdata.get('longitude'),
            'org': sdata.get('org'),
            'last_update': sdata.get('last_update'),
        }
    }
    return new_data


def nmap_data_parser(ndata):
    # Filters them all and chooses the first one on the list (which is the only one)
    n_ip_l = []
    for key in ndata['scan']:
        n_ip_l.append(key)
    ip = n_ip_l[0]

    port_objs = []
    _n_datalist = ndata.get('scan').get(ip).get('tcp')
    for p_num in _n_datalist:
        scripts = _n_datalist.get(p_num).get('script')

        obj = {
            'port': p_num,
            'state': _n_datalist.get(p_num).get('state'),
            'reason': _n_datalist.get(p_num).get('reason'),
            'name': _n_datalist.get(p_num).get('name'),
            'additional': {
                'product': _n_datalist.get(p_num).get('product'),
                'version': _n_datalist.get(p_num).get('version'),
                'extrainfo': _n_datalist.get(p_num).get('extrainfo'),
            },
            'script': scripts
        }

        port_objs.append(obj)

    new_data = {
        'nmap_command': ndata.get('nmap').get('command_line'),
        'ip': ip,
        'hostnames': ndata.get('scan').get(ip).get('hostnames'),
        'uptime': ndata.get('scan').get(ip).get('uptime'),
        'mqtt_ports': port_objs,
        'osmatch': ndata.get('scan').get(ip).get('osmatch'),
    }
    return new_data
