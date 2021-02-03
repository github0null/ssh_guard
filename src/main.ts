import * as fs from 'fs';
import * as os from 'os';
import * as child_process from 'child_process';

/* /var/log/btmp

oracle   ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)    
oracle   ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)    
oracle   ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)    
oracle   ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)    
oracle   ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)    
oracle   ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)    
root     ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)    
root     ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)    
root     ssh:notty    122.77.244.188   Wed Feb  3 07:36 - 07:36  (00:00)    
root     ssh:notty    122.77.244.188   Wed Feb  3 07:35 - 07:35  (00:00)    
root     ssh:notty    122.77.244.188   Wed Feb  3 07:35 - 07:35  (00:00)    
root     ssh:notty    122.77.244.188   Wed Feb  3 07:35 - 07:35  (00:00)    
root     ssh:notty    122.77.244.188   Wed Feb  3 07:35 - 07:35  (00:00)    
root     ssh:notty    122.77.244.188   Wed Feb  3 07:35 - 07:35  (00:00)
*/

/* /etc/hosts.deny

sshd:223.230.41.108:deny

*/

const btmp_path = '/var/log/btmp';
const host_deny_path = '/etc/hosts.deny';

const btmp_cmd = 'lastb';
const try_max = 3;
const task_interval = 1 * 1000 * 60;

const btmp_matcher = /^\s*\w+\s+[^\s]+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i;
const deny_host_matcher = /^\s*sshd:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):deny\s*$/i;

function append_to_host_deny(deny_host: string[]): number {

    if (deny_host.length == 0) {
        return deny_host.length;
    }

    const lines = fs.readFileSync(host_deny_path).toString().split(/\r\n|\n/g);
    const exsited_deny_list: string[] = []

    // get old deny list
    for (const line of lines) {
        const m_res = deny_host_matcher.exec(line);
        if (m_res && m_res.length > 1) {
            exsited_deny_list.push(m_res[1]);
        }
    }

    // filter existed ip
    const append_list = deny_host
        .filter((ip) => { return !exsited_deny_list.includes(ip); })
        .map((ip) => { return `sshd:${ip}:deny`; });

    // append to deny_list
    fs.appendFileSync(host_deny_path, append_list.join(os.EOL) + os.EOL);

    return append_list.length;
}

function clear_btmp_log() {
    fs.writeFileSync(btmp_path, '');
}

function main() {
    try {

        console.log(`[start]: at ${new Date().toLocaleString()}`);

        const log_lines = child_process.execSync(btmp_cmd).toString().split(/\r\n|\n/g);
        const cur_try_map = new Map<string, number>()

        // get deny list
        for (const line of log_lines) {
            const m_res = btmp_matcher.exec(line);
            if (m_res && m_res.length > 1) {
                const ip = m_res[1];
                const old_count = cur_try_map.get(ip) || 0;
                cur_try_map.set(ip, old_count + 1);
            }
        }

        // filter deny list
        const deny_list: string[] = [];
        for (const ip of cur_try_map.keys()) {
            if (<number>cur_try_map.get(ip) >= try_max) {
                deny_list.push(ip);
                console.log(`confirm ip: ${ip}`);
            } else {
                console.log(`ignore ip: ${ip}, try count: ${cur_try_map.get(ip)}`);
            }
        }

        // append to host deny list
        const real_num = append_to_host_deny(deny_list);

        // append ok, clear log
        if (real_num > 0) {
            clear_btmp_log(); // clear btmp log
        }

        console.log(`[done]: found ${deny_list.length} ip, deny: ${real_num} ip` + os.EOL);

    } catch (error) {
        console.log(error);
    }
}

/**
 * ************************************
 *              launch
 * ************************************
*/
main();
setInterval(() => main(), task_interval);
