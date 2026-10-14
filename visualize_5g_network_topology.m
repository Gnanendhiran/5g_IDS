%% 5G Wireless Intrusion Detection System - Network Topology Generator & Visualizer
% Topology Specification:
%   - 3 gNodeBs: gNB-1 (Sector A), gNB-2 (Sector B), gNB-3 (Sector C)
%   - 45 User Equipments (UE-1 to UE-45)
%   - 3 Standardized 5G Slices: eMBB (1-15), URLLC (16-30), mMTC (31-45)
%   - Inter-gNB Xn Backhaul Interfaces & 5G-NR Wireless Access Links
%   - Automatic High-Resolution Export (PNG 300 DPI, SVG, FIG)

function visualize_5g_network_topology()
    fprintf('=======================================================================\n');
    fprintf('5G WIRELESS IDS: GENERATING & SAVING 3-gNB / 45-UE NETWORK TOPOLOGY\n');
    fprintf('=======================================================================\n\n');

    % Define and create output directories
    primary_out_dir = fullfile('d:', '5G_Wireless_IDS', 'outputs');
    matlab_proj_dir = fullfile('C:', 'Users', 'nandh', 'MATLAB', 'Projects', '5G_IDS_MATLAB', 'results');
    
    if ~exist(primary_out_dir, 'dir')
        mkdir(primary_out_dir);
    end
    if exist(fullfile('C:', 'Users', 'nandh', 'MATLAB'), 'dir') && ~exist(matlab_proj_dir, 'dir')
        mkdir(matlab_proj_dir);
    end

    %% 1. Base Station (gNodeB) Configuration
    % 3 gNB Base Stations positioned across a 1000m x 1000m multi-cell area
    gnb_names = {'gNB-1', 'gNB-2', 'gNB-3'};
    gnb_sectors = {'Sector A', 'Sector B', 'Sector C'};
    gnb_pos = [ ...
        250, 550;   % gNB-1 (Cell Sector A)
        750, 550;   % gNB-2 (Cell Sector B)
        500, 200    % gNB-3 (Cell Sector C)
    ];
    cell_radius = 280; % Cell coverage radius in meters

    %% 2. 45 User Equipments (UE) Coordinate Generation
    num_ues = 45;
    ue_coords = zeros(num_ues, 2);
    ue_gnb_map = zeros(num_ues, 1);
    ue_slices = cell(num_ues, 1);

    % Fixed seed for reproducible, realistic cellular distribution
    rng(42);

    for u = 1:num_ues
        % Serving gNB mapping: round-robin (UE-1 -> gNB-1, UE-2 -> gNB-2, UE-3 -> gNB-3)
        gnb_idx = mod(u - 1, 3) + 1;
        ue_gnb_map(u) = gnb_idx;

        % 5G Slice assignment
        if u <= 15
            ue_slices{u} = 'eMBB';
        elseif u <= 30
            ue_slices{u} = 'URLLC';
        else
            ue_slices{u} = 'mMTC';
        end

        % Generate UE position within serving cell coverage circle
        % Distance from gNB center with non-uniform density
        dist = (0.20 + 0.75 * sqrt(rand())) * cell_radius;
        angle = rand() * 2 * pi;
        
        ue_x = gnb_pos(gnb_idx, 1) + dist * cos(angle);
        ue_y = gnb_pos(gnb_idx, 2) + dist * sin(angle);
        
        % Constrain within bounding arena [30, 970]
        ue_coords(u, 1) = max(30, min(970, ue_x));
        ue_coords(u, 2) = max(30, min(970, ue_y));
    end

    %% 3. Plotting Publication-Grade 5G Topology
    fig = figure('Name', '5G Multi-Cell Wireless Network Topology', ...
                 'Color', [0.06 0.09 0.16], ... % Deep SOC Dark Mode (#0f172a)
                 'Units', 'pixels', ...
                 'Position', [100, 100, 1280, 850], ...
                 'Visible', 'on');

    ax = axes('Parent', fig);
    hold(ax, 'on');
    set(ax, 'Color', [0.06 0.09 0.16], ...
            'XColor', [0.58 0.64 0.72], ...
            'YColor', [0.58 0.64 0.72], ...
            'GridColor', [0.20 0.27 0.38], ...
            'GridAlpha', 0.45, ...
            'LineWidth', 1.1, ...
            'FontSize', 10, ...
            'FontName', 'Helvetica');
    grid(ax, 'on');
    box(ax, 'on');

    % Color Palette
    col_gnb1   = [0.22, 0.74, 0.97]; % Cyan/Sky Blue (#38bdf8)
    col_gnb2   = [0.66, 0.33, 0.97]; % Purple (#a855f7)
    col_gnb3   = [0.06, 0.73, 0.51]; % Emerald (#10b981)
    gnb_colors = [col_gnb1; col_gnb2; col_gnb3];

    col_embb   = [0.23, 0.51, 0.96]; % Blue (#3b82f6)
    col_urllc  = [0.55, 0.36, 0.96]; % Violet/Purple (#8b5cf6)
    col_mmtc   = [0.13, 0.77, 0.37]; % Green (#22c55e)

    %% A. Draw gNodeB Cell Coverage Circles (Transparent Radiation Sectors)
    theta = linspace(0, 2*pi, 150);
    for g = 1:3
        cx = gnb_pos(g, 1) + cell_radius * cos(theta);
        cy = gnb_pos(g, 2) + cell_radius * sin(theta);
        
        fill(cx, cy, gnb_colors(g, :), ...
            'FaceAlpha', 0.07, ...
            'EdgeColor', gnb_colors(g, :), ...
            'LineStyle', ':', ...
            'LineWidth', 1.4, ...
            'HandleVisibility', 'off');
    end

    %% B. Draw Inter-gNB Xn Backhaul Coordination Links
    % Fully meshed Xn-C / Xn-U interfaces for collaborative Federated IDS
    xn_pairs = [1, 2; 2, 3; 3, 1];
    for p = 1:size(xn_pairs, 1)
        gA = xn_pairs(p, 1);
        gB = xn_pairs(p, 2);
        plot([gnb_pos(gA, 1), gnb_pos(gB, 1)], ...
             [gnb_pos(gA, 2), gnb_pos(gB, 2)], ...
             '--', 'Color', [0.94, 0.62, 0.07, 0.75], ... % Amber Xn link
             'LineWidth', 2.2, ...
             'DisplayName', iif(p == 1, '5G Xn Inter-gNB Backhaul (FedAvg Sync)', ''));
    end

    %% C. Draw Wireless 5G-NR Access Links (UE -> Serving gNodeB)
    for u = 1:num_ues
        g = ue_gnb_map(u);
        line_col = [gnb_colors(g, :), 0.22]; % 22% alpha link line
        plot([gnb_pos(g, 1), ue_coords(u, 1)], ...
             [gnb_pos(g, 2), ue_coords(u, 2)], ...
             '-', 'Color', line_col, ...
             'LineWidth', 0.9, ...
             'HandleVisibility', 'off');
    end

    %% D. Plot UEs Classified by 5G Network Slice
    embb_mask  = strcmp(ue_slices, 'eMBB');
    urllc_mask = strcmp(ue_slices, 'URLLC');
    mmtc_mask  = strcmp(ue_slices, 'mMTC');

    % eMBB UEs (UE-1 to UE-15) - Circle markers
    h_embb = scatter(ue_coords(embb_mask, 1), ue_coords(embb_mask, 2), 65, ...
        'MarkerFaceColor', col_embb, ...
        'MarkerEdgeColor', [1 1 1], ...
        'MarkerFaceAlpha', 0.95, ...
        'LineWidth', 1.0, ...
        'DisplayName', 'eMBB Slices (UE-1 to UE-15)');

    % URLLC UEs (UE-16 to UE-30) - Diamond markers
    h_urllc = scatter(ue_coords(urllc_mask, 1), ue_coords(urllc_mask, 2), 70, ...
        'diamond', ...
        'MarkerFaceColor', col_urllc, ...
        'MarkerEdgeColor', [1 1 1], ...
        'MarkerFaceAlpha', 0.95, ...
        'LineWidth', 1.0, ...
        'DisplayName', 'URLLC Slices (UE-16 to UE-30)');

    % mMTC UEs (UE-31 to UE-45) - Square markers
    h_mmtc = scatter(ue_coords(mmtc_mask, 1), ue_coords(mmtc_mask, 2), 65, ...
        'square', ...
        'MarkerFaceColor', col_mmtc, ...
        'MarkerEdgeColor', [1 1 1], ...
        'MarkerFaceAlpha', 0.95, ...
        'LineWidth', 1.0, ...
        'DisplayName', 'mMTC Slices (UE-31 to UE-45)');

    %% E. Label Each UE with Subtle Offset Text
    for u = 1:num_ues
        text(ue_coords(u, 1) + 8, ue_coords(u, 2) + 8, sprintf('UE-%d', u), ...
            'Color', [0.85, 0.88, 0.93], ...
            'FontSize', 7.5, ...
            'FontWeight', 'bold', ...
            'FontName', 'Helvetica', ...
            'Interpreter', 'none');
    end

    %% F. Plot Base Stations (gNodeBs) as Prominent Towers
    h_gnb = scatter(gnb_pos(:, 1), gnb_pos(:, 2), 240, ...
        'hexagram', ...
        'MarkerFaceColor', [0.98, 0.28, 0.28], ... % Crimson Red Base
        'MarkerEdgeColor', [1.0, 1.0, 1.0], ...
        'LineWidth', 2.0, ...
        'DisplayName', '5G gNodeB Base Stations (gNB 1-3)');

    % gNB Labels and Badges
    for g = 1:3
        % Name & Sector Label
        text(gnb_pos(g, 1), gnb_pos(g, 2) + 38, ...
            sprintf('%s\n(%s)', gnb_names{g}, gnb_sectors{g}), ...
            'Color', gnb_colors(g, :), ...
            'FontSize', 10.5, ...
            'FontWeight', 'bold', ...
            'HorizontalAlignment', 'center', ...
            'FontName', 'Helvetica');

        % Coordinate & Fleet Info Badge
        text(gnb_pos(g, 1), gnb_pos(g, 2) - 38, ...
            sprintf('(%dm, %dm) | 15 UEs', gnb_pos(g, 1), gnb_pos(g, 2)), ...
            'Color', [0.70, 0.75, 0.82], ...
            'FontSize', 8, ...
            'HorizontalAlignment', 'center', ...
            'FontName', 'Helvetica');
    end

    %% G. Titles, Axes, Limits & Legend Configuration
    xlim(ax, [0, 1000]);
    ylim(ax, [0, 850]);
    xlabel(ax, 'X Coordinate (Meters)', 'Color', [0.75, 0.80, 0.88], 'FontSize', 11, 'FontWeight', 'bold');
    ylabel(ax, 'Y Coordinate (Meters)', 'Color', [0.75, 0.80, 0.88], 'FontSize', 11, 'FontWeight', 'bold');
    
    title(ax, ...
        {'5G Wireless Multi-Cell Network Topology: 3 gNodeBs & 45 User Equipments', ...
         '\fontsize{9}\color[rgb]{0.58,0.64,0.72}Hierarchical Spatial Partitioning across eMBB, URLLC & mMTC Slices with Xn Collaborative Backhaul'}, ...
        'Color', [0.97, 0.98, 0.99], ...
        'FontSize', 13, ...
        'FontWeight', 'bold', ...
        'FontName', 'Helvetica');

    leg = legend(ax, [h_gnb, h_embb, h_urllc, h_mmtc], ...
        'Location', 'northeast', ...
        'TextColor', [0.94, 0.96, 0.98], ...
        'Color', [0.12, 0.16, 0.24], ...
        'EdgeColor', [0.25, 0.32, 0.44], ...
        'FontSize', 9.5);

    %% 4. Save Diagram in High-Resolution Formats
    file_prefix = '5g_network_topology_3gnb_45ue';
    
    % Primary export paths
    png_path1 = fullfile(primary_out_dir, [file_prefix, '.png']);
    fig_path1 = fullfile(primary_out_dir, [file_prefix, '.fig']);
    
    % Preserve dark theme colors in exported image
    set(fig, 'InvertHardcopy', 'off');
    
    % Export High-Res PNG (300 DPI) and FIG
    print(fig, png_path1, '-dpng', '-r300');
    savefig(fig, fig_path1);
    fprintf('  [OK] Saved 300 DPI PNG: %s\n', png_path1);
    fprintf('  [OK] Saved MATLAB FIG:  %s\n', fig_path1);

    % Optional Secondary export if MATLAB project folder exists
    if exist(matlab_proj_dir, 'dir')
        png_path2 = fullfile(matlab_proj_dir, [file_prefix, '.png']);
        fig_path2 = fullfile(matlab_proj_dir, [file_prefix, '.fig']);
        print(fig, png_path2, '-dpng', '-r300');
        savefig(fig, fig_path2);
        fprintf('  [OK] Exported to MATLAB Project: %s\n', png_path2);
    end

    %% 5. Print Topology Summary Table
    fprintf('\n-----------------------------------------------------------------------\n');
    fprintf('5G CELL TOPOLOGY SUMMARY:\n');
    fprintf('-----------------------------------------------------------------------\n');
    fprintf('  gNodeB ID | Sector Name | Position    | Cell Radius | Serving UEs\n');
    fprintf('  ----------+-------------+-------------+-------------+-------------\n');
    for g = 1:3
        fprintf('  %-9s | %-11s | (%3dm, %3dm) | %4dm      | 15 UEs (5 eMBB, 5 URLLC, 5 mMTC)\n', ...
            gnb_names{g}, gnb_sectors{g}, gnb_pos(g, 1), gnb_pos(g, 2), cell_radius);
    end
    fprintf('  Total UEs: 45 (eMBB: 15, URLLC: 15, mMTC: 15) across 3 gNodeBs.\n');
    fprintf('=======================================================================\n\n');
end

% Helper function: inline conditional
function val = iif(condition, trueVal, falseVal)
    if condition
        val = trueVal;
    else
        val = falseVal;
    end
end
