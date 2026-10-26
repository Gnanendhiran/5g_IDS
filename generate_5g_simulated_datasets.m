%% 5G Wireless Intrusion Detection System - Multi-Scenario Traffic Generator
% Generates 6 distinct, production-grade 5G simulation CSV datasets:
%   1. live_5g_sim_1_balanced_all_attacks.csv    (10,000 flows - All 8 attacks equally + 10% Normal)
%   2. live_5g_sim_2_volumetric_ddos_surge.csv   (10,000 flows - UDPFlood, SYNFlood, ICMPFlood + 10% Normal)
%   3. live_5g_sim_3_stealth_recon_scan.csv      (10,000 flows - TCPConnectScan, SYNScan, UDPScan + 10% Normal)
%   4. live_5g_sim_4_app_layer_starvation.csv    (10,000 flows - HTTPFlood, SlowrateDoS + 10% Normal)
%   5. live_5g_sim_5_iot_botnet_flood.csv        (10,000 flows - UDPScan, UDPFlood, ICMPFlood + 10% Normal)
%   6. live_5g_sim_6_coordinated_apt_campaign.csv(10,000 flows - Multi-Stage Recon, Evasion, Flood + 10% Normal)
%
% Architecture & Topology Specifications:
%   - Fleet: Exactly 45 User Equipments (UE-1 to UE-45)
%   - Infrastructure: Exactly 3 gNodeBs (gNB-1, gNB-2, gNB-3)
%   - Cell Sectors: Sector-Alpha (UE 1-15), Sector-Beta (UE 16-30), Sector-Gamma (UE 31-45)
%   - Normal Baseline: Exactly 10.00% Benign traffic (1,000 flows / 40 sequences of 25)
%   - Telemetry Schema: 15 standard fields calibrated to 5G-NIDD benchmark contract

function generate_5g_simulated_datasets()
    fprintf('=======================================================================\n');
    fprintf('5G WIRELESS IDS: MULTI-SCENARIO TRAFFIC DATASET SUITE GENERATOR\n');
    fprintf('=======================================================================\n\n');

    % Primary target directories
    dir_python = fullfile('D:', '5G_Wireless_IDS', 'outputs', 'simulated_traffic');
    dir_matlab = fullfile('C:', 'Users', 'nandh', 'MATLAB', 'Projects', '5G_IDS_MATLAB', 'results', 'traffic');

    if ~exist(dir_python, 'dir')
        mkdir(dir_python);
    end
    if exist(fullfile('C:', 'Users', 'nandh', 'MATLAB'), 'dir') && ~exist(dir_matlab, 'dir')
        mkdir(dir_matlab);
    end

    total_rows = 10000;
    rows_per_seq = 25;
    num_seq = total_rows / rows_per_seq; % 400 sequences
    benign_seq_count = 40; % Exactly 10% = 1,000 flows
    attack_seq_count = num_seq - benign_seq_count; % 360 sequences = 9,000 flows

    % Authentic 5G-NIDD statistical profiles
    profiles = get_5g_nidd_profiles();

    %% Scenario 1: Asymmetric Multi-Attack Benchmark (Every attack has a UNIQUE sequence count)
    fprintf('[1/6] Generating Scenario 1: Asymmetric Multi-Attack Benchmark (10%% Normal, distinct sequence counts)...\n');
    % Distinct sequence numbers: UDPFlood(72), HTTPFlood(62), SlowrateDoS(54), TCPConnectScan(48), SYNScan(38), UDPScan(34), SYNFlood(30), ICMPFlood(22)
    pool_s1 = [ ...
        repmat({'UDPFlood'}, 1, 72), ...
        repmat({'HTTPFlood'}, 1, 62), ...
        repmat({'SlowrateDoS'}, 1, 54), ...
        repmat({'TCPConnectScan'}, 1, 48), ...
        repmat({'SYNScan'}, 1, 38), ...
        repmat({'UDPScan'}, 1, 34), ...
        repmat({'SYNFlood'}, 1, 30), ...
        repmat({'ICMPFlood'}, 1, 22) ...
    ];
    pool_s1 = pool_s1(randperm(numel(pool_s1)));
    seq_s1 = build_interleaved_seqs(pool_s1, num_seq);
    export_dataset(seq_s1, profiles, rows_per_seq, 'live_5g_sim_1_balanced_all_attacks.csv', dir_python, dir_matlab);
    export_dataset(seq_s1, profiles, rows_per_seq, 'live_5g_sim_balanced_10pct_normal.csv', dir_python, dir_matlab);

    %% Scenario 2: Volumetric Flood Surge (Heavy UDP/SYN/ICMP Flooding - all attacks distinct)
    fprintf('\n[2/6] Generating Scenario 2: Volumetric Flood Surge (Distinct counts)...\n');
    % UDPFlood(85), HTTPFlood(65), SYNFlood(55), ICMPFlood(45), SlowrateDoS(35), TCPConnectScan(28), SYNScan(25), UDPScan(22)
    pool_s2 = [ ...
        repmat({'UDPFlood'}, 1, 85), ...
        repmat({'HTTPFlood'}, 1, 65), ...
        repmat({'SYNFlood'}, 1, 55), ...
        repmat({'ICMPFlood'}, 1, 45), ...
        repmat({'SlowrateDoS'}, 1, 35), ...
        repmat({'TCPConnectScan'}, 1, 28), ...
        repmat({'SYNScan'}, 1, 25), ...
        repmat({'UDPScan'}, 1, 22) ...
    ];
    pool_s2 = pool_s2(randperm(numel(pool_s2)));
    seq_s2 = build_interleaved_seqs(pool_s2, num_seq);
    export_dataset(seq_s2, profiles, rows_per_seq, 'live_5g_sim_2_volumetric_ddos_surge.csv', dir_python, dir_matlab);

    %% Scenario 3: Stealth Reconnaissance Focus (Heavy Scanning - all attacks distinct)
    fprintf('\n[3/6] Generating Scenario 3: Stealth Reconnaissance Focus (Distinct counts)...\n');
    % TCPConnectScan(82), SYNScan(68), UDPScan(58), SlowrateDoS(46), HTTPFlood(36), UDPFlood(32), SYNFlood(24), ICMPFlood(14)
    pool_s3 = [ ...
        repmat({'TCPConnectScan'}, 1, 82), ...
        repmat({'SYNScan'}, 1, 68), ...
        repmat({'UDPScan'}, 1, 58), ...
        repmat({'SlowrateDoS'}, 1, 46), ...
        repmat({'HTTPFlood'}, 1, 36), ...
        repmat({'UDPFlood'}, 1, 32), ...
        repmat({'SYNFlood'}, 1, 24), ...
        repmat({'ICMPFlood'}, 1, 14) ...
    ];
    pool_s3 = pool_s3(randperm(numel(pool_s3)));
    seq_s3 = build_interleaved_seqs(pool_s3, num_seq);
    export_dataset(seq_s3, profiles, rows_per_seq, 'live_5g_sim_3_stealth_recon_scan.csv', dir_python, dir_matlab);

    %% Scenario 4: Application-Layer Service Starvation (Heavy Slowrate/HTTP - all attacks distinct)
    fprintf('\n[4/6] Generating Scenario 4: App-Layer Starvation (Distinct counts)...\n');
    % SlowrateDoS(90), HTTPFlood(76), SYNFlood(52), TCPConnectScan(42), UDPFlood(34), SYNScan(28), ICMPFlood(20), UDPScan(18)
    pool_s4 = [ ...
        repmat({'SlowrateDoS'}, 1, 90), ...
        repmat({'HTTPFlood'}, 1, 76), ...
        repmat({'SYNFlood'}, 1, 52), ...
        repmat({'TCPConnectScan'}, 1, 42), ...
        repmat({'UDPFlood'}, 1, 34), ...
        repmat({'SYNScan'}, 1, 28), ...
        repmat({'ICMPFlood'}, 1, 20), ...
        repmat({'UDPScan'}, 1, 18) ...
    ];
    pool_s4 = pool_s4(randperm(numel(pool_s4)));
    seq_s4 = build_interleaved_seqs(pool_s4, num_seq);
    export_dataset(seq_s4, profiles, rows_per_seq, 'live_5g_sim_4_app_layer_starvation.csv', dir_python, dir_matlab);
    export_dataset(seq_s4, profiles, rows_per_seq, 'live_5g_sim_4_app_layer_service_starvation.csv', dir_python, dir_matlab);

    %% Scenario 5: IoT Sensor Fleet & Botnet Flood (Heavy ICMP/UDPScan - all attacks distinct)
    fprintf('\n[5/6] Generating Scenario 5: IoT Sensor Fleet & Botnet Flood (Distinct counts)...\n');
    % ICMPFlood(78), UDPScan(66), UDPFlood(56), SYNScan(46), HTTPFlood(38), SlowrateDoS(32), SYNFlood(26), TCPConnectScan(18)
    pool_s5 = [ ...
        repmat({'ICMPFlood'}, 1, 78), ...
        repmat({'UDPScan'}, 1, 66), ...
        repmat({'UDPFlood'}, 1, 56), ...
        repmat({'SYNScan'}, 1, 46), ...
        repmat({'HTTPFlood'}, 1, 38), ...
        repmat({'SlowrateDoS'}, 1, 32), ...
        repmat({'SYNFlood'}, 1, 26), ...
        repmat({'TCPConnectScan'}, 1, 18) ...
    ];
    pool_s5 = pool_s5(randperm(numel(pool_s5)));
    seq_s5 = build_interleaved_seqs(pool_s5, num_seq);
    export_dataset(seq_s5, profiles, rows_per_seq, 'live_5g_sim_5_iot_botnet_flood.csv', dir_python, dir_matlab);

    %% Scenario 6: Coordinated Multi-Stage APT Campaign (All 8 attacks distinct)
    fprintf('\n[6/6] Generating Scenario 6: Coordinated APT Campaign (Distinct counts)...\n');
    % HTTPFlood(74), SlowrateDoS(64), TCPConnectScan(54), UDPFlood(46), SYNFlood(42), SYNScan(36), UDPScan(26), ICMPFlood(18)
    pool_s6 = [ ...
        repmat({'HTTPFlood'}, 1, 74), ...
        repmat({'SlowrateDoS'}, 1, 64), ...
        repmat({'TCPConnectScan'}, 1, 54), ...
        repmat({'UDPFlood'}, 1, 46), ...
        repmat({'SYNFlood'}, 1, 42), ...
        repmat({'SYNScan'}, 1, 36), ...
        repmat({'UDPScan'}, 1, 26), ...
        repmat({'ICMPFlood'}, 1, 18) ...
    ];
    pool_s6 = pool_s6(randperm(numel(pool_s6)));
    seq_s6 = build_interleaved_seqs(pool_s6, num_seq);
    export_dataset(seq_s6, profiles, rows_per_seq, 'live_5g_sim_6_coordinated_apt_campaign.csv', dir_python, dir_matlab);

    %% Scenario 7: Four-Attack Cellular Perimeter Breach (Exactly 4 Attacks: 90 seqs each + 10% Normal)
    fprintf('\n[7/10] Generating Scenario 7: Four-Attack Cellular Perimeter Breach (No HTTPFlood)...\n');
    % UDPFlood(90), SYNFlood(90), TCPConnectScan(90), SYNScan(90)
    pool_s7 = [ ...
        repmat({'UDPFlood'}, 1, 90), ...
        repmat({'SYNFlood'}, 1, 90), ...
        repmat({'TCPConnectScan'}, 1, 90), ...
        repmat({'SYNScan'}, 1, 90) ...
    ];
    pool_s7 = pool_s7(randperm(numel(pool_s7)));
    seq_s7 = build_interleaved_seqs(pool_s7, num_seq);
    export_dataset(seq_s7, profiles, rows_per_seq, 'live_5g_sim_7_four_attack_perimeter.csv', dir_python, dir_matlab);

    %% Scenario 8: Tri-Attack Volumetric Inundation (Exactly 3 Attacks: 120 seqs each + 10% Normal)
    fprintf('\n[8/10] Generating Scenario 8: Tri-Attack Volumetric Inundation (No HTTPFlood)...\n');
    % UDPFlood(120), SYNFlood(120), ICMPFlood(120)
    pool_s8 = [ ...
        repmat({'UDPFlood'}, 1, 120), ...
        repmat({'SYNFlood'}, 1, 120), ...
        repmat({'ICMPFlood'}, 1, 120) ...
    ];
    pool_s8 = pool_s8(randperm(numel(pool_s8)));
    seq_s8 = build_interleaved_seqs(pool_s8, num_seq);
    export_dataset(seq_s8, profiles, rows_per_seq, 'live_5g_sim_8_tri_attack_surge.csv', dir_python, dir_matlab);

    %% Scenario 9: Six-Attack Advanced Persistent Vector (Exactly 6 Attacks: 60 seqs each + 10% Normal)
    fprintf('\n[9/10] Generating Scenario 9: Six-Attack Advanced Persistent Vector (No HTTPFlood)...\n');
    % SlowrateDoS(60), TCPConnectScan(60), SYNScan(60), UDPScan(60), SYNFlood(60), ICMPFlood(60)
    pool_s9 = [ ...
        repmat({'SlowrateDoS'}, 1, 60), ...
        repmat({'TCPConnectScan'}, 1, 60), ...
        repmat({'SYNScan'}, 1, 60), ...
        repmat({'UDPScan'}, 1, 60), ...
        repmat({'SYNFlood'}, 1, 60), ...
        repmat({'ICMPFlood'}, 1, 60) ...
    ];
    pool_s9 = pool_s9(randperm(numel(pool_s9)));
    seq_s9 = build_interleaved_seqs(pool_s9, num_seq);
    export_dataset(seq_s9, profiles, rows_per_seq, 'live_5g_sim_9_six_attack_advanced.csv', dir_python, dir_matlab);

    %% Scenario 10: Penta-Attack Telemetry Benchmark (Exactly 5 Attacks: 72 seqs each + 10% Normal)
    fprintf('\n[10/10] Generating Scenario 10: Penta-Attack Telemetry Benchmark (5 Attacks)...\n');
    % HTTPFlood(72), SlowrateDoS(72), UDPFlood(72), SYNFlood(72), TCPConnectScan(72)
    pool_s10 = [ ...
        repmat({'HTTPFlood'}, 1, 72), ...
        repmat({'SlowrateDoS'}, 1, 72), ...
        repmat({'UDPFlood'}, 1, 72), ...
        repmat({'SYNFlood'}, 1, 72), ...
        repmat({'TCPConnectScan'}, 1, 72) ...
    ];
    pool_s10 = pool_s10(randperm(numel(pool_s10)));
    seq_s10 = build_interleaved_seqs(pool_s10, num_seq);
    export_dataset(seq_s10, profiles, rows_per_seq, 'live_5g_sim_10_penta_attack_telemetry.csv', dir_python, dir_matlab);

    fprintf('\n=======================================================================\n');
    fprintf('SUCCESS: All 10 Simulation Datasets Generated & Calibrated to 5G-NIDD!\n');
    fprintf('  - Target Directory: %s\n', dir_python);
    fprintf('  - 10,000 flows per CSV (400 sequences, 25 flows/seq)\n');
    fprintf('  - Fleet: 45 UEs, 3 gNodeBs, 3 Cell Sectors (Alpha, Beta, Gamma)\n');
    fprintf('  - Normal Baseline: Exactly 10.00%% Benign flows in each dataset\n');
    fprintf('=======================================================================\n\n');
end

%% Helper: Interleave Benign Every 10th Sequence for Exactly 10% Normal
function seqs = build_interleaved_seqs(attack_pool, total_seqs)
    seqs = cell(1, total_seqs);
    cursor = 1;
    for s = 1:total_seqs
        if mod(s, 10) == 0
            seqs{s} = 'Benign';
        else
            seqs{s} = attack_pool{cursor};
            cursor = cursor + 1;
        end
    end
end

%% Helper: Generate physical records and export CSV
function export_dataset(seq_attacks, profiles, rows_per_seq, filename, dir1, dir2)
    num_seq = numel(seq_attacks);
    total_rows = num_seq * rows_per_seq;

    Timestamps = strings(total_rows, 1);
    UEIDs = zeros(total_rows, 1);
    gNB_IDs = strings(total_rows, 1);
    Sectors = strings(total_rows, 1);
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

    base_time = datetime(2026, 10, 14, 10, 0, 0);
    row_cursor = 1;

    for s = 1:num_seq
        att = seq_attacks{s};
        prof = profiles(att);

        % Exactly 45 UEs & 3 gNodeBs topology
        ue_id = mod(s - 1, 45) + 1;
        gnb_id = sprintf('gNB-%d', mod(ue_id - 1, 3) + 1);

        % 5G Multi-Cell Sector Mapping
        if ue_id <= 15
            sector_name = 'Sector-Alpha';
        elseif ue_id <= 30
            sector_name = 'Sector-Beta';
        else
            sector_name = 'Sector-Gamma';
        end

        seq_time = base_time + seconds((s - 1) * 1.5);

        for step = 1:rows_per_seq
            curr_time = seq_time + milliseconds((step - 1) * 40);

            Timestamps(row_cursor) = datestr(curr_time, 'yyyy-mm-dd HH:MM:SS.FFF');
            UEIDs(row_cursor) = ue_id;
            gNB_IDs(row_cursor) = gnb_id;
            Sectors(row_cursor) = sector_name;
            Protocols(row_cursor) = prof.proto;

            % Calibrated feature synthesis
            Durations(row_cursor) = round(prof.dur(1) + (prof.dur(2) - prof.dur(1)) * rand(), 4);
            pkts = randi([prof.pkts(1), prof.pkts(2)]);
            PacketCounts(row_cursor) = pkts;

            if strcmp(prof.bytes_mode, 'fixed_per_pkt')
                bytes_val = pkts * round(prof.mean_sz(1));
            else
                bytes_val = randi([prof.bytes(1), prof.bytes(2)]);
            end
            BytesCol(row_cursor) = bytes_val;

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

    T = table(Timestamps, UEIDs, gNB_IDs, Sectors, Protocols, ...
        Durations, PacketCounts, BytesCol, PacketRates, MeanPacketSizes, ...
        MinPacketSizes, MaxPacketSizes, LossRates, TrafficTypes, AttackTypes, ...
        'VariableNames', { ...
            'Timestamp', 'UEID', 'gNB_ID', 'Sector', 'Protocol', ...
            'Duration', 'PacketCount', 'Bytes', 'PacketRate', 'MeanPacketSize', ...
            'MinPacketSize', 'MaxPacketSize', 'LossRate', 'TrafficType', 'AttackType' ...
        });

    p1 = fullfile(dir1, filename);
    writetable(T, p1);
    fprintf('  [OK] Exported: %s (10,000 rows, 400 sequences)\n', p1);

    if exist(dir2, 'dir')
        p2 = fullfile(dir2, filename);
        writetable(T, p2);
        fprintf('  [OK] Exported to MATLAB Project: %s\n', p2);
    end
end

%% Helper: Authentic 5G-NIDD Statistical Feature Profiles
function p = get_5g_nidd_profiles()
    p = containers.Map();

    % 1. Benign (Normal Legitimate 5G Telemetry - Web, streaming, telemetry)
    p('Benign') = struct( ...
        'dur', [0.20, 2.50], 'pkts', [4, 18], 'bytes', [300, 15000], ...
        'rate', [10.0, 200.0], 'mean_sz', [80.0, 250.0], 'min_sz', 40.0, 'max_sz', 1460.0, ...
        'loss', [0.0, 0.01], 'proto', 'TCP', 'traffic', 'Benign', 'bytes_mode', 'range');

    % 2. UDPFlood (Volumetric UDP Flooding - 42-byte fixed NetFlow records)
    p('UDPFlood') = struct( ...
        'dur', [0.50, 2.50], 'pkts', [1, 3], 'bytes', [42, 126], ...
        'rate', [0.10, 1.50], 'mean_sz', [42.0, 42.0], 'min_sz', 42.0, 'max_sz', 42.0, ...
        'loss', [0.0, 0.0], 'proto', 'UDP', 'traffic', 'Malicious', 'bytes_mode', 'fixed_per_pkt');

    % 3. HTTPFlood (App-Layer HTTP GET/POST Flood)
    p('HTTPFlood') = struct( ...
        'dur', [0.10, 3.50], 'pkts', [3, 16], 'bytes', [200, 5000], ...
        'rate', [500.0, 8000.0], 'mean_sz', [66.0, 110.0], 'min_sz', 54.0, 'max_sz', 1460.0, ...
        'loss', [0.0, 0.05], 'proto', 'TCP', 'traffic', 'Malicious', 'bytes_mode', 'range');

    % 4. SlowrateDoS (Slowloris / Slow-HTTP connection starvation)
    p('SlowrateDoS') = struct( ...
        'dur', [2.00, 5.00], 'pkts', [6, 12], 'bytes', [350, 950], ...
        'rate', [200.0, 2000.0], 'mean_sz', [70.0, 80.0], 'min_sz', 40.0, 'max_sz', 120.0, ...
        'loss', [0.0, 0.02], 'proto', 'TCP', 'traffic', 'Malicious', 'bytes_mode', 'range');

    % 5. TCPConnectScan (Full 3-way handshake port discovery)
    p('TCPConnectScan') = struct( ...
        'dur', [0.001, 0.020], 'pkts', [1, 1], 'bytes', [70, 78], ...
        'rate', [0.5, 5.0], 'mean_sz', [70.0, 78.0], 'min_sz', 70.0, 'max_sz', 78.0, ...
        'loss', [0.0, 0.20], 'proto', 'TCP', 'traffic', 'Malicious', 'bytes_mode', 'range');

    % 6. SYNScan (Stealth half-open TCP SYN scanning)
    p('SYNScan') = struct( ...
        'dur', [0.0001, 0.0010], 'pkts', [1, 1], 'bytes', [54, 58], ...
        'rate', [0.5, 5.0], 'mean_sz', [54.0, 58.0], 'min_sz', 54.0, 'max_sz', 58.0, ...
        'loss', [0.0, 0.0], 'proto', 'TCP', 'traffic', 'Malicious', 'bytes_mode', 'range');

    % 7. UDPScan (Closed-port ICMP unreachable discovery)
    p('UDPScan') = struct( ...
        'dur', [0.0001, 0.0010], 'pkts', [1, 1], 'bytes', [40, 46], ...
        'rate', [0.5, 5.0], 'mean_sz', [40.0, 46.0], 'min_sz', 40.0, 'max_sz', 46.0, ...
        'loss', [0.0, 0.0], 'proto', 'UDP', 'traffic', 'Malicious', 'bytes_mode', 'range');

    % 8. SYNFlood (TCP SYN queue exhaustion attack)
    p('SYNFlood') = struct( ...
        'dur', [0.010, 0.080], 'pkts', [2, 4], 'bytes', [120, 240], ...
        'rate', [50.0, 200.0], 'mean_sz', [54.0, 60.0], 'min_sz', 54.0, 'max_sz', 60.0, ...
        'loss', [0.01, 0.20], 'proto', 'TCP', 'traffic', 'Malicious', 'bytes_mode', 'range');

    % 9. ICMPFlood (Ping echo request volumetric burst)
    p('ICMPFlood') = struct( ...
        'dur', [0.001, 0.005], 'pkts', [2, 2], 'bytes', [80, 88], ...
        'rate', [300.0, 600.0], 'mean_sz', [42.0, 42.0], 'min_sz', 42.0, 'max_sz', 42.0, ...
        'loss', [0.0, 0.0], 'proto', 'ICMP', 'traffic', 'Malicious', 'bytes_mode', 'fixed_per_pkt');
end
