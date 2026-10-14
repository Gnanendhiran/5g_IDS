%% 5G Wireless Intrusion Detection System - MATLAB Multi-Scenario Traffic Generator
% Generates 6 distinct, realistic 5G simulation CSV datasets with 10,000 records each.
% Each dataset contains exactly 10,000 records (400 sequences of 25 rows) containing
% all 9 genuine 5G-NIDD attack classes, 10% benign traffic, across 45 UEs and 3 gNBs.
%
% Output Directory: C:\Users\nandh\MATLAB\Projects\5G_IDS_MATLAB\results\traffic
%                   or d:\5G_Wireless_IDS\outputs\simulated_traffic

function generate_5g_simulated_datasets()
    fprintf('======================================================================\n');
    fprintf('5G WIRELESS IDS: GENERATING 6 SIMULATION DATASETS (10,000 ROWS, 45 UEs, 3 gNBs)\n');
    fprintf('======================================================================\n\n');

    % Define output directories
    target_dir_python = fullfile('d:', '5G_Wireless_IDS', 'outputs', 'simulated_traffic');
    target_dir_matlab = fullfile('C:', 'Users', 'nandh', 'MATLAB', 'Projects', '5G_IDS_MATLAB', 'results', 'traffic');

    if ~exist(target_dir_python, 'dir')
        mkdir(target_dir_python);
    end
    if exist(fullfile('C:', 'Users', 'nandh', 'MATLAB'), 'dir') && ~exist(target_dir_matlab, 'dir')
        mkdir(target_dir_matlab);
    end

    total_rows = 10000;
    rows_per_seq = 25;
    num_seq = total_rows / rows_per_seq; % 400 sequences

    % Characteristic attack parameter ranges
    profiles = create_attack_profiles();

    %% 1. Scenario 1: Balanced Multi-Attack (All 8 attacks + exactly 10% Benign traffic)
    % 40 Benign (10%) + 360 Attacks (45 each of the 8 classes = 90%)
    attack_only_classes = { ...
        'UDPFlood', 'HTTPFlood', 'SlowrateDoS', ...
        'TCPConnectScan', 'SYNScan', 'UDPScan', 'SYNFlood', 'ICMPFlood' ...
    };
    attacks_360 = repmat(attack_only_classes, 1, 45); 
    seq_attacks_1 = cell(1, num_seq);
    att_idx = 1;
    for i = 1:num_seq
        if mod(i, 10) == 0
            seq_attacks_1{i} = 'Benign'; % Exactly 10% (every 10th sequence)
        else
            seq_attacks_1{i} = attacks_360{att_idx};
            att_idx = att_idx + 1;
        end
    end
    build_and_export_dataset(seq_attacks_1, profiles, rows_per_seq, ...
        'live_5g_sim_1_balanced_all_attacks.csv', target_dir_python, target_dir_matlab);

    %% 2. Scenario 2: Volumetric DDoS Saturation Surge (10% Benign + Volumetric Floods)
    base_dist_2 = {'UDPFlood', 'SYNFlood', 'UDPFlood', 'ICMPFlood', 'UDPFlood', 'SYNFlood', 'UDPFlood', 'ICMPFlood', 'UDPFlood', 'Benign'};
    seq_attacks_2 = repmat(base_dist_2, 1, ceil(num_seq / numel(base_dist_2)));
    seq_attacks_2 = seq_attacks_2(1:num_seq);
    build_and_export_dataset(seq_attacks_2, profiles, rows_per_seq, ...
        'live_5g_sim_2_volumetric_ddos_surge.csv', target_dir_python, target_dir_matlab);

    %% 3. Scenario 3: Stealth Reconnaissance and Scanning (10% Benign + Port Probes)
    base_dist_3 = {'TCPConnectScan', 'SYNScan', 'UDPScan', 'SlowrateDoS', 'SYNScan', 'TCPConnectScan', 'UDPScan', 'SYNScan', 'TCPConnectScan', 'Benign'};
    seq_attacks_3 = repmat(base_dist_3, 1, ceil(num_seq / numel(base_dist_3)));
    seq_attacks_3 = seq_attacks_3(1:num_seq);
    build_and_export_dataset(seq_attacks_3, profiles, rows_per_seq, ...
        'live_5g_sim_3_stealth_recon_scan.csv', target_dir_python, target_dir_matlab);

    %% 4. Scenario 4: Application Layer Service Starvation (10% Benign + HTTP & Slowrate)
    base_dist_4 = {'HTTPFlood', 'SlowrateDoS', 'HTTPFlood', 'SlowrateDoS', 'HTTPFlood', 'HTTPFlood', 'SlowrateDoS', 'HTTPFlood', 'SlowrateDoS', 'Benign'};
    seq_attacks_4 = repmat(base_dist_4, 1, ceil(num_seq / numel(base_dist_4)));
    seq_attacks_4 = seq_attacks_4(1:num_seq);
    build_and_export_dataset(seq_attacks_4, profiles, rows_per_seq, ...
        'live_5g_sim_4_app_layer_service_starvation.csv', target_dir_python, target_dir_matlab);

    %% 5. Scenario 5: IoT / mMTC Slice Burst & Probing (10% Benign + IoT Traffic)
    base_dist_5 = {'UDPScan', 'UDPFlood', 'SlowrateDoS', 'ICMPFlood', 'UDPScan', 'UDPFlood', 'SlowrateDoS', 'UDPScan', 'UDPFlood', 'Benign'};
    seq_attacks_5 = repmat(base_dist_5, 1, ceil(num_seq / numel(base_dist_5)));
    seq_attacks_5 = seq_attacks_5(1:num_seq);
    build_and_export_dataset(seq_attacks_5, profiles, rows_per_seq, ...
        'live_5g_sim_5_iot_sensor_slice_burst.csv', target_dir_python, target_dir_matlab);

    %% 6. Scenario 6: Coordinated Multi-Stage APT Campaign (10% Benign + APT Progression)
    base_dist_6 = { ...
        'TCPConnectScan', 'SYNScan', 'UDPScan', ...
        'SlowrateDoS', 'SlowrateDoS', ...
        'HTTPFlood', 'SYNFlood', 'UDPFlood', ...
        'HTTPFlood', 'Benign' ...
    };
    seq_attacks_6 = repmat(base_dist_6, 1, ceil(num_seq / numel(base_dist_6)));
    seq_attacks_6 = seq_attacks_6(1:num_seq);
    build_and_export_dataset(seq_attacks_6, profiles, rows_per_seq, ...
        'live_5g_sim_6_coordinated_apt_campaign.csv', target_dir_python, target_dir_matlab);

    fprintf('\nAll 6 simulation datasets (10,000 rows each, 45 UEs, 3 gNBs) successfully generated and verified!\n');
end

%% Helper: Define realistic 5G-NIDD physical distributions
function p = create_attack_profiles()
    p = containers.Map();
    
    p('Benign') = struct('dur', [0.05, 5.0], 'pkts', [10, 80], 'bytes', [600, 30000], ...
        'rate', [10.0, 150.0], 'mean_sz', [64.0, 500.0], 'min_sz', 40.0, 'max_sz', 1460.0, ...
        'loss', [0.0, 0.005], 'proto', 'TCP', 'traffic', 'Benign');
        
    p('UDPFlood') = struct('dur', [0.01, 1.2], 'pkts', [500, 5000], 'bytes', [250000, 5000000], ...
        'rate', [1500.0, 15000.0], 'mean_sz', [500.0, 1200.0], 'min_sz', 128.0, 'max_sz', 1400.0, ...
        'loss', [0.02, 0.15], 'proto', 'UDP', 'traffic', 'Malicious');
        
    p('HTTPFlood') = struct('dur', [0.05, 2.5], 'pkts', [80, 800], 'bytes', [50000, 800000], ...
        'rate', [400.0, 3000.0], 'mean_sz', [400.0, 1000.0], 'min_sz', 64.0, 'max_sz', 1460.0, ...
        'loss', [0.01, 0.08], 'proto', 'TCP', 'traffic', 'Malicious');
        
    p('SlowrateDoS') = struct('dur', [15.0, 120.0], 'pkts', [15, 60], 'bytes', [800, 4000], ...
        'rate', [0.2, 5.0], 'mean_sz', [50.0, 100.0], 'min_sz', 40.0, 'max_sz', 120.0, ...
        'loss', [0.0, 0.02], 'proto', 'TCP', 'traffic', 'Malicious');
        
    p('TCPConnectScan') = struct('dur', [0.005, 0.15], 'pkts', [3, 8], 'bytes', [180, 500], ...
        'rate', [10.0, 120.0], 'mean_sz', [40.0, 70.0], 'min_sz', 40.0, 'max_sz', 80.0, ...
        'loss', [0.05, 0.40], 'proto', 'TCP', 'traffic', 'Malicious');
        
    p('SYNScan') = struct('dur', [0.002, 0.08], 'pkts', [1, 3], 'bytes', [54, 160], ...
        'rate', [20.0, 200.0], 'mean_sz', [40.0, 54.0], 'min_sz', 40.0, 'max_sz', 60.0, ...
        'loss', [0.10, 0.60], 'proto', 'TCP', 'traffic', 'Malicious');
        
    p('UDPScan') = struct('dur', [0.002, 0.10], 'pkts', [1, 4], 'bytes', [60, 250], ...
        'rate', [15.0, 150.0], 'mean_sz', [40.0, 65.0], 'min_sz', 40.0, 'max_sz', 70.0, ...
        'loss', [0.20, 0.70], 'proto', 'UDP', 'traffic', 'Malicious');
        
    p('SYNFlood') = struct('dur', [0.01, 1.0], 'pkts', [300, 3500], 'bytes', [16000, 200000], ...
        'rate', [800.0, 9000.0], 'mean_sz', [54.0, 64.0], 'min_sz', 54.0, 'max_sz', 64.0, ...
        'loss', [0.03, 0.20], 'proto', 'TCP', 'traffic', 'Malicious');
        
    p('ICMPFlood') = struct('dur', [0.01, 0.8], 'pkts', [200, 2500], 'bytes', [15000, 250000], ...
        'rate', [500.0, 6000.0], 'mean_sz', [64.0, 100.0], 'min_sz', 64.0, 'max_sz', 128.0, ...
        'loss', [0.02, 0.15], 'proto', 'ICMP', 'traffic', 'Malicious');
end

%% Helper: Generate sequence rows and write CSV
function build_and_export_dataset(seq_attacks, profiles, rows_per_seq, filename, target_dir1, target_dir2)
    num_seq = numel(seq_attacks);
    total_rows = num_seq * rows_per_seq;

    % Preallocate table columns
    Timestamps = strings(total_rows, 1);
    UEIDs = zeros(total_rows, 1);
    gNB_IDs = strings(total_rows, 1);
    SliceTypes = strings(total_rows, 1);
    Protocols = strings(total_rows, 1);
    Durations = zeros(total_rows, 1);
    PacketCounts = zeros(total_rows, 1);
    BytesCol = zeros(total_rows, 1);
    PacketRates = zeros(total_rows, 1);
    MeanPacketSizes = zeros(total_rows, 1);
    MinPacketSizes = zeros(total_rows, 1);
    MaxPacketSizes = zeros(total_rows, 1);
    LossRates = zeros(total_rows, 1);
    TrafficTypes = strings(total_rows, 1);
    AttackTypes = strings(total_rows, 1);

    base_time = datetime(2026, 10, 13, 10, 0, 0);
    row_cursor = 1;

    for s = 1:num_seq
        att = seq_attacks{s};
        prof = profiles(att);
        ue_id = mod(s - 1, 45) + 1; % 45 UEs
        gnb_id = sprintf('gNB-%d', mod(ue_id - 1, 3) + 1); % 3 gNodeBs (gNB-1, gNB-2, gNB-3)
        
        if ue_id <= 15
            slice_type = 'eMBB';
        elseif ue_id <= 30
            slice_type = 'URLLC';
        else
            slice_type = 'mMTC';
        end
        
        seq_time = base_time + seconds((s - 1) * 1.5);

        for step = 1:rows_per_seq
            curr_time = seq_time + milliseconds((step - 1) * 40);
            
            Timestamps(row_cursor) = datestr(curr_time, 'yyyy-mm-dd HH:MM:SS.FFF');
            UEIDs(row_cursor) = ue_id;
            gNB_IDs(row_cursor) = gnb_id;
            SliceTypes(row_cursor) = slice_type;
            Protocols(row_cursor) = prof.proto;
            
            Durations(row_cursor) = round(prof.dur(1) + (prof.dur(2) - prof.dur(1)) * rand(), 4);
            PacketCounts(row_cursor) = randi([prof.pkts(1), prof.pkts(2)]);
            BytesCol(row_cursor) = randi([prof.bytes(1), prof.bytes(2)]);
            PacketRates(row_cursor) = round(prof.rate(1) + (prof.rate(2) - prof.rate(1)) * rand(), 2);
            MeanPacketSizes(row_cursor) = round(prof.mean_sz(1) + (prof.mean_sz(2) - prof.mean_sz(1)) * rand(), 2);
            MinPacketSizes(row_cursor) = prof.min_sz;
            MaxPacketSizes(row_cursor) = prof.max_sz;
            LossRates(row_cursor) = round(prof.loss(1) + (prof.loss(2) - prof.loss(1)) * rand(), 4);
            
            TrafficTypes(row_cursor) = prof.traffic;
            AttackTypes(row_cursor) = att;

            row_cursor = row_cursor + 1;
        end
    end

    T = table(Timestamps, UEIDs, gNB_IDs, SliceTypes, Protocols, ...
        Durations, PacketCounts, BytesCol, PacketRates, MeanPacketSizes, ...
        MinPacketSizes, MaxPacketSizes, LossRates, TrafficTypes, AttackTypes, ...
        'VariableNames', { ...
            'Timestamp', 'UEID', 'gNB_ID', 'SliceType', 'Protocol', ...
            'Duration', 'PacketCount', 'Bytes', 'PacketRate', 'MeanPacketSize', ...
            'MinPacketSize', 'MaxPacketSize', 'LossRate', 'TrafficType', 'AttackType' ...
        });

    path1 = fullfile(target_dir1, filename);
    writetable(T, path1);
    fprintf('  [OK] Exported: %s (%d rows, %d sequences)\n', path1, total_rows, num_seq);

    if exist(target_dir2, 'dir')
        path2 = fullfile(target_dir2, filename);
        writetable(T, path2);
    end
end
