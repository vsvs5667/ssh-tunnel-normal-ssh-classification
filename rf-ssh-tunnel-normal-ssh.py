import os

from nfstream import NFStreamer, NFPlugin
from flowcontainer.extractor import extract
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

pd.set_option('display.max_columns', None)  # 显示完整的列
pd.set_option('display.max_rows', None)  # 显示完整的行
pd.set_option('display.max_colwidth', None)  # 显示所有单元格内容
pd.set_option('display.expand_frame_repr', False)  # 设置不折叠数据

# 读取PCAP文件


def time_delta(pcap_path, src_ip, src_port, dst_ip, dst_port):
    result = extract(pcap_path, extension=['frame.time'])
    for key in result.keys():
        value = result[key]
        if value.src == src_ip and value.sport == src_port:
            timestamps = value.ip_timestamps
            time_delta = np.diff(timestamps)
            # print(time_delta)
            min_time_delta = np.min(time_delta)
            max_time_delta = np.max(time_delta)
            avg_time_delta = np.mean(time_delta)
            std_time_delta = np.std(time_delta)
            return min_time_delta, max_time_delta, avg_time_delta, std_time_delta
        elif value.src == dst_ip and value.sport == dst_port:
            timestamps = value.ip_timestamps
            time_delta = np.diff(timestamps)
            # print(time_delta)
            min_time_delta = np.min(time_delta)
            max_time_delta = np.max(time_delta)
            avg_time_delta = np.mean(time_delta)
            std_time_delta = np.std(time_delta)
            return min_time_delta, max_time_delta, avg_time_delta, std_time_delta

        # for i in range(len(value.extension['frame.time_delta'])):
        #     time_delta.append(value.extension['frame.time_delta'][i][0])
        # time_delta[0] = 0.000000000
        # print(f'{pcap_path}中每个流中数据包的时间间隔{time_delta}')


# class PacketTimeDelta(NFPlugin):
#     def on_init(self, packet, flow):
#         flow.udps.packet_gaps = [0]  # 初始化一个列表来保存数据包间隔
#         flow.udps.last_packet_timestamp = packet.time  # 保存当前数据包的时间戳
#
#     def on_update(self, packet, flow):
#         current_timestamp = packet.time  # 获取当前数据包的时间戳
#         time_difference = current_timestamp - flow.udps.last_packet_timestamp  # 计算数据包间隔
#         flow.udps.packet_gaps.append(time_difference)  # 将数据包间隔添加到列表中
#         flow.udps.last_packet_timestamp = current_timestamp  # 更新上一个数据包的时间戳
#
#     def on_expire(self, flow):
#         #print(f'Packet gaps in flow {flow.id}: {flow.udps.packet_gaps}')  # 在流结束时输出数据包间隔列表
#         return flow.udps.packet_gaps

def ssh_flow_extract(pcap_path):
    streamer = NFStreamer(source=pcap_path,
                          decode_tunnels=True,
                          bpf_filter=None,
                          promiscuous_mode=True,
                          snapshot_length=1536,
                          idle_timeout=120,
                          active_timeout=1800,
                          accounting_mode=0,
                          udps=None,
                          n_dissections=20,
                          statistical_analysis=True,
                          splt_analysis=20,
                          n_meters=0,
                          max_nflows=0,
                          performance_report=0,
                          system_visibility_mode=0,
                          system_visibility_poll_ms=100
                          )
    ssh_flows1 = []
    ssh_flows2 = []
    # 遍历streamer中的每一个流
    for flow in streamer:
        # 检查流的application_name是否为'SSH'
        if flow.bidirectional_packets >= 6 and (flow.application_is_guessed != 0 and flow.application_confidence != 6) and flow.src2dst_duration_ms !=0 and flow.dst2src_duration_ms !=0 and flow.src2dst_stddev_ps !=0 and flow.dst2src_stddev_ps !=0:
            # 如果是，那么将这个流添加到列表中
            # print(flow)
            ssh_flows1.append(flow)
    for flow in ssh_flows1:
        flow_dict = {
            "src_ip": flow.src_ip,
            "src_mac": flow.src_mac,
            "src_port": flow.src_port,
            "dst_ip": flow.dst_ip,
            "dst_mac": flow.dst_mac,
            "dst_port": flow.dst_port,
            "protocol": flow.protocol,
            "ip_version": flow.ip_version,
            "vlan_id": flow.vlan_id,
            "tunnel_id": flow.tunnel_id,
            "bidirectional_first_seen_ms": flow.bidirectional_first_seen_ms,
            "bidirectional_last_seen_ms": flow.bidirectional_last_seen_ms,
            "bidirectional_duration_ms": flow.bidirectional_duration_ms,
            "bidirectional_packets": flow.bidirectional_packets,
            "bidirectional_bytes": flow.bidirectional_bytes,
            "src2dst_first_seen_ms": flow.src2dst_first_seen_ms,
            "src2dst_last_seen_ms": flow.src2dst_last_seen_ms,
            "src2dst_duration_ms": flow.src2dst_duration_ms,
            "src2dst_packets": flow.src2dst_packets,
            "src2dst_bytes": flow.src2dst_bytes,
            "dst2src_first_seen_ms": flow.dst2src_first_seen_ms,
            "dst2src_last_seen_ms": flow.dst2src_last_seen_ms,
            "dst2src_duration_ms": flow.dst2src_duration_ms,
            "dst2src_packets": flow.dst2src_packets,
            "dst2src_bytes": flow.dst2src_bytes,
            "bidirectional_min_ps": flow.bidirectional_min_ps,
            "bidirectional_mean_ps": flow.bidirectional_mean_ps,
            "bidirectional_stddev_ps": flow.bidirectional_stddev_ps,
            "bidirectional_max_ps": flow.bidirectional_max_ps,
            "src2dst_min_ps": flow.src2dst_min_ps,
            "src2dst_mean_ps": flow.src2dst_mean_ps,
            "src2dst_stddev_ps": flow.src2dst_stddev_ps,
            "src2dst_max_ps": flow.src2dst_max_ps,
            "dst2src_min_ps": flow.dst2src_min_ps,
            "dst2src_mean_ps": flow.dst2src_mean_ps,
            "dst2src_stddev_ps": flow.dst2src_stddev_ps,
            "dst2src_max_ps": flow.dst2src_max_ps,
            "splt_direction": flow.splt_direction,
            "splt_ps": flow.splt_ps,
            "splt_piat_ms": flow.splt_piat_ms,
            "application_name": flow.application_name,
            "application_category_name": flow.application_category_name,
            "application_is_guessed": flow.application_is_guessed,
            "application_confidence": flow.application_confidence,
            "pcap_path": pcap_path
            # 添加更多你感兴趣的字段...
        }
        ssh_flows2.append(flow_dict)
    df_ssh = pd.DataFrame(ssh_flows2)
    df_ssh['label'] = 0
    df_ssh['label'] = df_ssh.apply(get_label, axis=1)
    # print(df_ssh)
    for index, row in df_ssh.iterrows():
        src_ip = row['src_ip']
        src_port = row['src_port']
        dst_ip = row['dst_ip']
        dst_port = row['dst_port']
        # print(src_ip,src_port)
        min_time_delta, max_time_delta, avg_time_delta, std_time_delta = time_delta(pcap_path, src_ip, src_port, dst_ip, dst_port)
        df_ssh.loc[index, 'min_time_delta'] = min_time_delta
        df_ssh.loc[index, 'max_time_delta'] = max_time_delta
        df_ssh.loc[index, 'avg_time_delta'] = avg_time_delta
        df_ssh.loc[index, 'std_time_delta'] = std_time_delta
    return df_ssh

    # print(X)
    # print(y)
def rf_train_predict(df_ssh):
    X = df_ssh[['bidirectional_duration_ms',
                'bidirectional_bytes',
                'bidirectional_min_ps',
                'bidirectional_mean_ps',
                'bidirectional_stddev_ps',
                'bidirectional_max_ps',
                'src2dst_duration_ms',
                'src2dst_bytes',
                'src2dst_min_ps',
                'src2dst_mean_ps',
                'src2dst_stddev_ps',
                'src2dst_max_ps',
                'dst2src_duration_ms',
                'dst2src_bytes',
                'dst2src_min_ps',
                'dst2src_mean_ps',
                'dst2src_stddev_ps',
                'dst2src_max_ps',
                'min_time_delta',
                'max_time_delta',
                'avg_time_delta',
                'std_time_delta']].values
    y = df_ssh['label'].values
    print(X)
    print(y)
    # X = np.array(X)
    # Y = np.array(Y)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    # print(X_train)
    # print(y_train)
    model = RandomForestClassifier(n_estimators=200, max_depth=10, max_features='sqrt')
    model.fit(X_train, y_train)
    importances = model.feature_importances_
    score = model.score(X_test, y_test)
    print('importances:', importances)
    print('Accuracy:', score)
    pcap_path_predict = '/home/frank/Desktop/ssh_pcap/175.24.203.152_test'
    combined_df_ssh_new = pd.DataFrame()
    for file in os.listdir(pcap_path_predict):
        pcap_path_predict = '/home/frank/Desktop/ssh_pcap/175.24.203.152_test/' + file
        print(pcap_path_predict)
        df_ssh_new = ssh_flow_extract(pcap_path_predict)
        combined_df_ssh_new =  combined_df_ssh_new.append(df_ssh_new, ignore_index=True)
    print(combined_df_ssh_new)
    X_new = combined_df_ssh_new[['bidirectional_duration_ms',
                                 'bidirectional_bytes',
                                 'bidirectional_min_ps',
                                 'bidirectional_mean_ps',
                                 'bidirectional_stddev_ps',
                                 'bidirectional_max_ps',
                                 'src2dst_duration_ms',
                                 'src2dst_bytes',
                                 'src2dst_min_ps',
                                 'src2dst_mean_ps',
                                 'src2dst_stddev_ps',
                                 'src2dst_max_ps',
                                 'dst2src_duration_ms',
                                 'dst2src_bytes',
                                 'dst2src_min_ps',
                                 'dst2src_mean_ps',
                                 'dst2src_stddev_ps',
                                 'dst2src_max_ps',
                                 'min_time_delta',
                                 'max_time_delta',
                                 'avg_time_delta',
                                 'std_time_delta']].values
    y_pred = model.predict(X_new)
    print(y_pred)
    y_true = combined_df_ssh_new['label'].values
    print(classification_report(y_true, y_pred, digits=5))

def get_label(row):
    if row['src_ip'] == '114.132.246.101' or row['src_ip'] == '43.138.2.231' or row['dst_ip'] == '43.138.2.231' or row['dst_ip'] == '114.132.246.101' or '2006-02' in row['pcap_path'] or '2006-03' in row['pcap_path']:
        return 1
    else:
        return 0


if __name__ == '__main__':
    pcap_path = '/home/frank/Desktop/ssh_pcap/175.24.203.152_train'
    combined_df_ssh = pd.DataFrame()
    for file in os.listdir(pcap_path):
        pcap_path = '/home/frank/Desktop/ssh_pcap/175.24.203.152_train/' + file
        # print(pcap_path)
        df_ssh = ssh_flow_extract(pcap_path)
        combined_df_ssh = combined_df_ssh.append(df_ssh, ignore_index=True)
    print(combined_df_ssh)
    rf_train_predict(combined_df_ssh)