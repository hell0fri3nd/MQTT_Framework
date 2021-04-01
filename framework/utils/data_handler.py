def nmap_shodan_data_merger(ipaddr, ndata, sdata):
    ip = str(ipaddr)

    shod_mqtt_data = []

    # Filter mqtt ports only
    for elem in sdata['data']:
        if elem['_shodan']['module'] == 'mqtt' or elem['_shodan']['module'] == 'secure-mqtt':
            shod_mqtt_data.append(elem)

    # Filter ports object
    port_objs = []
    _n_datalist = ndata['scan'][ip]['tcp']
    for p_num in _n_datalist:
        for d in shod_mqtt_data:
            # Equal port number and equal service running
            # (sometimes on shodan port 8883 is used as https server)
            if p_num == d['port'] and _n_datalist[p_num]['name'] == d['_shodan']['module']:
                # Check if script exists
                scripts = {}
                if _n_datalist[p_num]['script'] is not None:
                    scripts = _n_datalist[p_num]['script']

                obj = {
                    'port': p_num,
                    'state': _n_datalist[p_num]['state'],
                    'reason': _n_datalist[p_num]['reason'],
                    'name': _n_datalist[p_num]['name'],
                    'additional': {
                        'isp': d['isp'],
                        'org': d['org'],
                        'location': d['location'],
                        'hostnames': d['hostnames'],
                        'product': _n_datalist[p_num]['product'],
                        'version': _n_datalist[p_num]['version'],
                        'extrainfo': _n_datalist[p_num]['extrainfo'],
                    },
                    'mqtt_code': d['mqtt']['code'],
                    'messages': d['mqtt']['messages'],
                    'script': scripts,
                    'data': d['data']
                }

                port_objs.append(obj)

    new_data = {
        'nmap_command': ndata['nmap']['command_line'],
        'hostnames': ndata['scan'][ip]['hostnames'],
        'uptime': ndata['scan'][ip]['uptime'],
        'mqtt_ports': port_objs,
        'ports': sdata['ports'],
        'osmatch': ndata['scan'][ip]['osmatch'],
        'location': {
            'city': sdata['city'],
            'postal_code': sdata['postal_code'],
            'region_code': sdata['region_code'],
            'country_name': sdata['country_name'],
            'latitude': sdata['latitude'],
            'longitude': sdata['longitude'],
            'org': sdata['org'],
            'last_update': sdata['last_update'],
        }
    }
    return new_data
