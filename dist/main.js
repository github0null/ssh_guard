"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const child_process = __importStar(require("child_process"));
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
const task_interval = 5 * 1000 * 60;
const btmp_matcher = /^\s*\w+\s+[^\s]+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i;
const deny_host_matcher = /^\s*sshd:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):deny\s*$/i;
function append_to_host_deny(deny_host) {
    const lines = fs.readFileSync(host_deny_path).toString().split(/\r\n|\n/g);
    const exsited_deny_list = [];
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
    fs.appendFileSync(host_deny_path, append_list.join(os.EOL));
    return append_list.length;
}
function clear_btmp_log() {
    fs.writeFileSync(btmp_path, '');
}
function main() {
    try {
        console.log(`[start]: at ${new Date().toLocaleString()}`);
        const log_lines = child_process.execSync(btmp_cmd).toString().split(/\r\n|\n/g);
        const cur_try_map = new Map();
        console.log(`read btmp logs:`);
        console.log('\t' + log_lines.join(`\t${os.EOL}`));
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
        const deny_list = [];
        for (const ip of cur_try_map.keys()) {
            if (cur_try_map.get(ip) > try_max) {
                deny_list.push(ip);
            }
        }
        console.log(`found ${deny_list.length} ip, deny them !`);
        // append to host deny list
        const real_num = append_to_host_deny(deny_list);
        // clear btmp log
        if (deny_list.length > 0) {
            clear_btmp_log();
        }
        console.log(`[done]: real deny number: ${real_num}${os.EOL}`);
    }
    catch (error) {
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
