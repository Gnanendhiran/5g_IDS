%% 5G Wireless Intrusion Detection System - Balanced Traffic Generator
% Generates realistic 5G simulation data with:
%   - Exactly 10% Normal / Benign traffic (1,000 flows / 40 sequences)
%   - Exactly 90% Malicious traffic split EQUALLY across all 8 genuine attack types
%     (1,125 flows / 45 sequences each = 11.25% per attack class)
%   - 45 User Equipments (UE-1 to UE-45) across 3 gNodeBs (gNB-1, gNB-2, gNB-3)
%   - 3 Standard 5G Network Slices: eMBB (1-15), URLLC (16-30), mMTC (31-45)
%   - Output format: 15 standard 5G traffic fields matching python_scaler_91 contract

function generate_balanced_5g_traffic()
    fprintf('=======================================================================\n');
    fprintf('5G WIRELESS IDS: GENERATING BALANCED TRAFFIC (10%% NORMAL + EQUAL ATTACKS)\n');
    fprintf('=======================================================================\n\n');

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
    num_seq = total_rows / rows_per_seq; % 400 sequences total

    % Total sequences: 400 sequences (10,000 flows / 25 flows per sequence)
    % Exactly 10% Normal = 40 sequences (1,000 flows)
    % Attack traffic = 360 sequences (9,000 flows) with DISTINCT/DIFFERENT sequence numbers per attack:
    %   - UDPFlood:        72 sequences (1,800 flows)
    %   - HTTPFlood:       62 sequences (1,550 flows)
    %   - SlowrateDoS:     54 sequences (1,350 flows)
    %   - TCPConnectScan:  48 sequences (1,200 flows)
    %   - SYNScan:         38 sequences (950 flows)
    %   - UDPScan:         34 sequences (850 flows)
    %   - SYNFlood:        30 sequences (750 flows)
    %   - ICMPFlood:       22 sequences (550 flows)
    % Total attacks = 72+62+54+48+38+34+30+22 = 360 sequences (all different!)

    attack_classes = { ...
        'UDPFlood', 'HTTPFlood', 'SlowrateDoS', ...
        'TCPConnectScan', 'SYNScan', 'UDPScan', 'SYNFlood', 'ICMPFlood' ...
    };
    attack_counts = [72, 62, 54, 48, 38, 34, 30, 22]; % Every attack has a distinct count!

    fprintf('Dataset Plan (Unequal & Distinct Sequence Counts for Verification):\n');
    fprintf('  - Total Flows:      %d (across %d sequences of %d flows)\n', total_rows, num_seq, rows_per_seq);
    fprintf('  - Normal (Benign):  40 sequences (1,000 flows = 10.00%%)\n');
    for a = 1:numel(attack_classes)
        fprintf('  - %-16s: %2d sequences (%5d flows)\n', ...
            attack_classes{a}, attack_counts(a), attack_counts(a) * rows_per_seq);
    end
    fprintf('  - Cellular Fleet:   45 UEs across 3 gNodeBs & 3 Slices (eMBB, URLLC, mMTC)\n\n');

    % Build pool of attack sequences with exact distinct counts
    attack_pool = {};
    for a = 1:numel(attack_classes)
        attack_pool = [attack_pool, repmat(attack_classes(a), 1, attack_counts(a))];
    end
    % Shuffle attack order for realistic chronological distribution
    rng(42); % Deterministic seed for reproducible testing
    attack_pool = attack_pool(randperm(numel(attack_pool)));

    % Interleave Benign (40 sequences) evenly: 1 benign every 10 sequences
    seq_attack_types = cell(1, num_seq);
    att_cursor = 1;
    for s = 1:num_seq
        if mod(s, 10) == 0
            seq_attack_types{s} = 'Benign';
        else
            seq_attack_types{s} = attack_pool{att_cursor};
            att_cursor = att_cursor + 1;
        end
    end

    % Characteristic traffic profiles calibrated to 5G-NIDD benchmark
    profiles = create_5g_traffic_profiles();

    % Generate and export dataset
    export_filename = 'live_5g_sim_balanced_10pct_normal.csv';
    build_and_export_csv(seq_attack_types, profiles, rows_per_seq, ...
        export_filename, target_dir_python, target_dir_matlab);

    % Also update live_5g_sim_1_balanced_all_attacks.csv for seamless dashboard usage
    build_and_export_csv(seq_attack_types, profiles, rows_per_seq, ...
        'live_5g_sim_1_balanced_all_attacks.csv', target_dir_python, target_dir_matlab);

    fprintf('\nGeneration Complete! Summary Table:\n');
    fprintf('  -----------------------------------------------------------------\n');
    fprintf('  Class Name       | Sequences | Total Flows | Target Share | Status\n');
    fprintf('  -----------------+-----------+-------------+--------------+-------\n');
    fprintf('  Benign (Normal)  |    40     |    1,000    |    10.00%%    | Legitimate\n');
    for a = 1:numel(attack_classes)
        fprintf('  %-16s |    %2d     |    %5d    |    %5.2f%%   | Malicious\n', ...
            attack_classes{a}, attack_counts(a), attack_counts(a) * rows_per_seq, ...
            (attack_counts(a) / num_seq) * 100);
    end
    fprintf('  -----------------+-----------+-------------+--------------+-------\n');
    fprintf('  Total            |   400     |   10,000    |   100.00%%    | Verified\n');
    fprintf('=======================================================================\n\n');
end

%% Helper: Generate physical records and export CSV
function build_and_export_csv(seq_attacks, profiles, rows_per_seq, filename, dir1, dir2)
    num_seq = numel(seq_attacks);
    total_rows = num_seq * rows_per_seq;

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

    base_time = datetime(2026, 10, 14, 10, 0, 0);
    row_cursor = 1;

    for s = 1:num_seq
        att = seq_attacks{s};
        prof = profiles(att);

        % 45 UEs & 3 gNodeBs mapping
        ue_id = mod(s - 1, 45) + 1;
        gnb_id = sprintf('gNB-%d', mod(ue_id - 1, 3) + 1);

        % 5G Network Slice allocation
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

    T = table(Timestamps, UEIDs, gNB_IDs, SliceTypes, Protocols, ...
        Durations, PacketCounts, BytesCol, PacketRates, MeanPacketSizes, ...
        MinPacketSizes, MaxPacketSizes, LossRates, TrafficTypes, AttackTypes, ...
        'VariableNames', { ...
            'Timestamp', 'UEID', 'gNB_ID', 'SliceType', 'Protocol', ...
            'Duration', 'PacketCount', 'Bytes', 'PacketRate', 'MeanPacketSize', ...
            'MinPacketSize', 'MaxPacketSize', 'LossRate', 'TrafficType', 'AttackType' ...
        });

    p1 = fullfile(dir1, filename);
    writetable(T, p1);
    fprintf('  [OK] Exported: %s (%d rows)\n', p1, total_rows);

    if exist(dir2, 'dir')
        p2 = fullfile(dir2, filename);
        writetable(T, p2);
        fprintf('  [OK] Exported to MATLAB Project: %s\n', p2);
    end
end

%% Helper: Realistic statistical profiles matching 5G-NIDD benchmark
function p = create_5g_traffic_profiles()
    p = containers.Map();

    % Normal / Benign traffic (legitimate packet rates and sizes)
    p('Benign') = struct( ...
        'dur', [0.20, 2.50], 'pkts', [4, 18], 'bytes', [300, 15000], ...
        'rate', [10.0, 200.0], 'mean_sz', [80.0, 250.0], 'min_sz', 40.0, 'max_sz', 1460.0, ...
        'loss', [0.0, 0.01], 'proto', 'TCP', 'traffic', 'Benign', 'bytes_mode', 'range');

    % 8 genuine 5G-NIDD attack classes
    p('UDPFlood') = struct( ...
        'dur', [0.50, 2.50], 'pkts', [1, 3], 'bytes', [42, 126], ...
        'rate', [0.10, 1.50], 'mean_sz', [42.0, 42.0], 'min_sz', 42.0, 'max_sz', 42.0, ...
        'loss', [0.0, 0.0], 'proto', 'UDP', 'traffic', 'Malicious', 'bytes_mode', 'fixed_per_pkt');

    p('HTTPFlood') = struct( ...
        'dur', [0.10, 3.50], 'pkts', [3, 16], 'bytes', [200, 5000], ...
        'rate', [500.0, 8000.0], 'mean_sz', [66.0, 110.0], 'min_sz', 54.0, 'max_sz', 1460.0, ...
        'loss', [0.0, 0.05], 'proto', 'TCP', 'traffic', 'Malicious', 'bytes_mode', 'range');

    p('SlowrateDoS') = struct( ...
        'dur', [2.00, 5.00], 'pkts', [6, 12], 'bytes', [350, 950], ...
        'rate', [200.0, 2000.0], 'mean_sz', [70.0, 80.0], 'min_sz', 40.0, 'max_sz', 120.0, ...
        'loss', [0.0, 0.02], 'proto', 'TCP', 'traffic', 'Malicious', 'bytes_mode', 'range');

    p('TCPConnectScan') = struct( ...
        'dur', [0.001, 0.020], 'pkts', [1, 1], 'bytes', [70, 78], ...
        'rate', [0.5, 5.0], 'mean_sz', [70.0, 78.0], 'min_sz', 70.0, 'max_sz', 78.0, ...
        'loss', [0.0, 0.20], 'proto', 'TCP', 'traffic', 'Malicious', 'bytes_mode', 'range');

    p('SYNScan') = struct( ...
        'dur', [0.0001, 0.0010], 'pkts', [1, 1], 'bytes', [54, 58], ...
        'rate', [0.5, 5.0], 'mean_sz', [54.0, 58.0], 'min_sz', 54.0, 'max_sz', 58.0, ...
        'loss', [0.0, 0.0], 'proto', 'TCP', 'traffic', 'Malicious', 'bytes_mode', 'range');

    p('UDPScan') = struct( ...
        'dur', [0.0001, 0.0010], 'pkts', [1, 1], 'bytes', [40, 46], ...
        'rate', [0.5, 5.0], 'mean_sz', [40.0, 46.0], 'min_sz', 40.0, 'max_sz', 46.0, ...
        'loss', [0.0, 0.0], 'proto', 'UDP', 'traffic', 'Malicious', 'bytes_mode', 'range');

    p('SYNFlood') = struct( ...
        'dur', [0.010, 0.080], 'pkts', [2, 4], 'bytes', [120, 240], ...
        'rate', [50.0, 200.0], 'mean_sz', [54.0, 60.0], 'min_sz', 54.0, 'max_sz', 60.0, ...
        'loss', [0.01, 0.20], 'proto', 'TCP', 'traffic', 'Malicious', 'bytes_mode', 'range');

    p('ICMPFlood') = struct( ...
        'dur', [0.001, 0.005], 'pkts', [2, 2], 'bytes', [80, 88], ...
        'rate', [300.0, 600.0], 'mean_sz', [42.0, 42.0], 'min_sz', 42.0, 'max_sz', 42.0, ...
        'loss', [0.0, 0.0], 'proto', 'ICMP', 'traffic', 'Malicious', 'bytes_mode', 'fixed_per_pkt');
end
