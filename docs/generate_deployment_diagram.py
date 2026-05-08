"""
EDR Platform — UML Deployment Diagram Generator
Generates a professional high-resolution deployment architecture diagram.
"""

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
from matplotlib.path import Path
import matplotlib.patheffects as pe
import numpy as np
import os

# ──────────────────────────────────────────────────────────────────────────────
# COLOR PALETTE
# ──────────────────────────────────────────────────────────────────────────────
COLORS = {
    # Server node
    'server_face':      '#1a2744',
    'server_top':       '#243556',
    'server_right':     '#0f1a2e',
    'server_border':    '#4a6fa5',
    'server_label':     '#e8edf5',

    # Docker zone
    'docker_bg':        '#1e2f4d',
    'docker_border':    '#3a5a8c',

    # Components
    'comp_dashboard':   '#2196F3',
    'comp_connmgr':     '#00897B',
    'comp_detection':   '#E65100',
    'comp_response':    '#C62828',
    'comp_postgres':    '#1565C0',
    'comp_kafka':       '#4E342E',
    'comp_redis':       '#B71C1C',

    # Endpoint node
    'endpoint_face':    '#b3d4fc',
    'endpoint_top':     '#cde3fd',
    'endpoint_right':   '#8bb8f0',
    'endpoint_border':  '#3a7bd5',
    'endpoint_label':   '#1a2744',

    # Agent
    'agent_face':       '#4a90d9',
    'agent_border':     '#2563a0',
    'agent_text':       '#ffffff',

    # Arrows
    'arrow_grpc':       '#00e676',
    'arrow_kafka':      '#ff9800',
    'arrow_detect':     '#ff5252',
    'arrow_response':   '#ab47bc',
    'arrow_db':         '#42a5f5',
    'arrow_rest':       '#26c6da',
    'arrow_cmd':        '#fdd835',

    # Background
    'bg':               '#0d1117',
    'title':            '#ffffff',
    'subtitle':         '#8b949e',
    'legend_bg':        '#161b22',
    'legend_border':    '#30363d',
}


def draw_3d_box(ax, x, y, w, h, depth_x=12, depth_y=10,
                face_color='#1a2744', top_color='#243556',
                right_color='#0f1a2e', border_color='#4a6fa5',
                linewidth=1.8, alpha=1.0):
    """Draw a UML-style 3D node box."""
    # Front face
    front = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=2",
        facecolor=face_color, edgecolor=border_color,
        linewidth=linewidth, alpha=alpha, zorder=2
    )
    ax.add_patch(front)

    # Top face (parallelogram)
    top_verts = [
        (x, y + h),
        (x + depth_x, y + h + depth_y),
        (x + w + depth_x, y + h + depth_y),
        (x + w, y + h),
        (x, y + h),
    ]
    top_codes = [Path.MOVETO, Path.LINETO, Path.LINETO, Path.LINETO, Path.CLOSEPOLY]
    top_path = Path(top_verts, top_codes)
    top_patch = mpatches.PathPatch(
        top_path, facecolor=top_color, edgecolor=border_color,
        linewidth=linewidth, alpha=alpha, zorder=3
    )
    ax.add_patch(top_patch)

    # Right face (parallelogram)
    right_verts = [
        (x + w, y),
        (x + w, y + h),
        (x + w + depth_x, y + h + depth_y),
        (x + w + depth_x, y + depth_y),
        (x + w, y),
    ]
    right_codes = [Path.MOVETO, Path.LINETO, Path.LINETO, Path.LINETO, Path.CLOSEPOLY]
    right_path = Path(right_verts, right_codes)
    right_patch = mpatches.PathPatch(
        right_path, facecolor=right_color, edgecolor=border_color,
        linewidth=linewidth, alpha=alpha, zorder=3
    )
    ax.add_patch(right_patch)

    return front


def draw_component(ax, x, y, w, h, label, color, text_color='#ffffff',
                   icon=None, fontsize=8.5, bold=True):
    """Draw a UML component box with optional icon text."""
    comp = FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=1.5",
        facecolor=color, edgecolor='#ffffff',
        linewidth=1.2, alpha=0.92, zorder=5
    )
    ax.add_patch(comp)

    # Small UML component tabs
    tab_w, tab_h = 6, 3
    for ty in [y + h * 0.35, y + h * 0.6]:
        tab = FancyBboxPatch(
            (x - 3, ty), tab_w, tab_h,
            boxstyle="round,pad=0.3",
            facecolor=color, edgecolor='#ffffff',
            linewidth=0.8, alpha=0.92, zorder=6
        )
        ax.add_patch(tab)

    weight = 'bold' if bold else 'normal'
    if icon:
        ax.text(x + w / 2, y + h / 2 + 2, icon, fontsize=fontsize + 3,
                ha='center', va='center', color=text_color, zorder=7,
                fontfamily='Segoe UI Emoji')
        ax.text(x + w / 2, y + h / 2 - 4, label, fontsize=fontsize,
                ha='center', va='center', color=text_color, weight=weight,
                zorder=7, fontfamily='Segoe UI')
    else:
        ax.text(x + w / 2, y + h / 2, label, fontsize=fontsize,
                ha='center', va='center', color=text_color, weight=weight,
                zorder=7, fontfamily='Segoe UI')


def draw_arrow(ax, start, end, color, label, fontsize=7, labelpos=0.5,
               style='->', linewidth=1.5, offset=(0, 3), curved=False,
               connectionstyle=None, zorder=4, linestyle='-'):
    """Draw a labeled arrow between two points."""
    if connectionstyle:
        arrow = FancyArrowPatch(
            start, end,
            arrowstyle=style,
            color=color,
            linewidth=linewidth,
            connectionstyle=connectionstyle,
            zorder=zorder,
            linestyle=linestyle,
            mutation_scale=14,
        )
    else:
        arrow = FancyArrowPatch(
            start, end,
            arrowstyle=style,
            color=color,
            linewidth=linewidth,
            zorder=zorder,
            linestyle=linestyle,
            mutation_scale=14,
        )
    ax.add_patch(arrow)

    # Label
    mid_x = start[0] + (end[0] - start[0]) * labelpos + offset[0]
    mid_y = start[1] + (end[1] - start[1]) * labelpos + offset[1]
    ax.text(mid_x, mid_y, label, fontsize=fontsize, color=color,
            ha='center', va='center', zorder=10, fontfamily='Segoe UI',
            weight='bold',
            path_effects=[pe.withStroke(linewidth=2.5, foreground=COLORS['bg'])])


def main():
    fig, ax = plt.subplots(1, 1, figsize=(26, 18), dpi=200)
    fig.patch.set_facecolor(COLORS['bg'])
    ax.set_facecolor(COLORS['bg'])
    ax.set_xlim(-10, 520)
    ax.set_ylim(-30, 390)
    ax.set_aspect('equal')
    ax.axis('off')

    # ── TITLE ────────────────────────────────────────────────────────────────
    ax.text(255, 378, 'EDR Platform — Deployment Architecture',
            fontsize=22, ha='center', va='center',
            color=COLORS['title'], weight='bold', fontfamily='Segoe UI',
            path_effects=[pe.withStroke(linewidth=3, foreground='#000000')])
    ax.text(255, 366, 'UML Deployment Diagram  ·  Open-Source EDR  ·  Docker Compose Orchestration',
            fontsize=10, ha='center', va='center',
            color=COLORS['subtitle'], fontfamily='Segoe UI')

    # ── Divider line ─────────────────────────────────────────────────────────
    ax.plot([20, 490], [358, 358], color='#30363d', linewidth=1, zorder=1)

    # ══════════════════════════════════════════════════════════════════════════
    # SERVER NODE
    # ══════════════════════════════════════════════════════════════════════════
    server_x, server_y = 20, 110
    server_w, server_h = 310, 230
    draw_3d_box(ax, server_x, server_y, server_w, server_h,
                depth_x=14, depth_y=12,
                face_color=COLORS['server_face'],
                top_color=COLORS['server_top'],
                right_color=COLORS['server_right'],
                border_color=COLORS['server_border'],
                linewidth=2.2)

    # Node stereotype & label
    ax.text(server_x + 12, server_y + server_h - 10,
            '«device»', fontsize=8, color='#8ba4cc',
            style='italic', fontfamily='Segoe UI', zorder=10)
    ax.text(server_x + 12, server_y + server_h - 22,
            'EDR Server Node', fontsize=13, color=COLORS['server_label'],
            weight='bold', fontfamily='Segoe UI', zorder=10)
    ax.text(server_x + 12, server_y + server_h - 34,
            'Ubuntu 22.04 / Windows 11  |  4 CPU · 8 GB RAM',
            fontsize=7.5, color='#7a8da8', fontfamily='Segoe UI', zorder=10)

    # ── Docker Compose zone ──────────────────────────────────────────────────
    dock_x, dock_y = server_x + 10, server_y + 8
    dock_w, dock_h = server_w - 20, server_h - 55
    docker_rect = FancyBboxPatch(
        (dock_x, dock_y), dock_w, dock_h,
        boxstyle="round,pad=2",
        facecolor=COLORS['docker_bg'], edgecolor=COLORS['docker_border'],
        linewidth=1.2, linestyle='--', alpha=0.85, zorder=3
    )
    ax.add_patch(docker_rect)
    ax.text(dock_x + 5, dock_y + dock_h - 8,
            '«execution environment»  Docker Compose',
            fontsize=7.5, color='#5a8abf', style='italic',
            fontfamily='Segoe UI', zorder=10)

    # ── Components inside Docker ─────────────────────────────────────────────
    comp_w, comp_h = 82, 32

    # Row 1 — top
    row1_y = dock_y + dock_h - 55

    draw_component(ax, dock_x + 8, row1_y, comp_w, comp_h,
                   'EDR Dashboard\n(React/TS) :30088',
                   COLORS['comp_dashboard'], fontsize=7.5)

    draw_component(ax, dock_x + 100, row1_y, comp_w, comp_h,
                   'Connection\nManager (Go)',
                   COLORS['comp_connmgr'], fontsize=7.5)

    draw_component(ax, dock_x + 192, row1_y, comp_w + 5, comp_h,
                   'Detection Engine\n(Sigma Rules)',
                   COLORS['comp_detection'], fontsize=7.5)

    # Row 2 — middle
    row2_y = row1_y - 45

    draw_component(ax, dock_x + 8, row2_y, comp_w, comp_h,
                   'Response\nEngine',
                   COLORS['comp_response'], fontsize=7.5)

    draw_component(ax, dock_x + 100, row2_y, comp_w, comp_h,
                   'Apache Kafka\n(Msg Broker)',
                   COLORS['comp_kafka'], fontsize=7.5)

    draw_component(ax, dock_x + 192, row2_y, comp_w + 5, comp_h,
                   'PostgreSQL\nDatabase',
                   COLORS['comp_postgres'], fontsize=7.5)

    # Row 3 — bottom
    row3_y = row2_y - 45

    draw_component(ax, dock_x + 55, row3_y, comp_w, comp_h,
                   'Redis\n(Cache)',
                   COLORS['comp_redis'], fontsize=7.5)

    # ══════════════════════════════════════════════════════════════════════════
    # ENDPOINT NODES (3 Windows endpoints)
    # ══════════════════════════════════════════════════════════════════════════
    endpoint_w, endpoint_h = 110, 80
    endpoints = [
        {'label': 'Endpoint 1', 'x': 390, 'y': 275},
        {'label': 'Endpoint 2', 'x': 390, 'y': 175},
        {'label': 'Endpoint 3', 'x': 390, 'y': 75},
    ]

    for ep in endpoints:
        draw_3d_box(ax, ep['x'], ep['y'], endpoint_w, endpoint_h,
                    depth_x=10, depth_y=8,
                    face_color=COLORS['endpoint_face'],
                    top_color=COLORS['endpoint_top'],
                    right_color=COLORS['endpoint_right'],
                    border_color=COLORS['endpoint_border'],
                    linewidth=1.6)

        # Node labels
        ax.text(ep['x'] + 8, ep['y'] + endpoint_h - 10,
                '«device»', fontsize=6.5, color='#2c5282',
                style='italic', fontfamily='Segoe UI', zorder=10)
        ax.text(ep['x'] + 8, ep['y'] + endpoint_h - 20,
                ep['label'], fontsize=10, color=COLORS['endpoint_label'],
                weight='bold', fontfamily='Segoe UI', zorder=10)
        ax.text(ep['x'] + 8, ep['y'] + endpoint_h - 29,
                'Windows OS', fontsize=7, color='#3a5a82',
                fontfamily='Segoe UI', zorder=10)

        # Agent component inside
        draw_component(ax, ep['x'] + 12, ep['y'] + 8, 86, 28,
                       'EDR Agent (Go)\nEnrollment Token',
                       COLORS['agent_face'], text_color=COLORS['agent_text'],
                       fontsize=7)

    # ══════════════════════════════════════════════════════════════════════════
    # COMMUNICATION ARROWS
    # ══════════════════════════════════════════════════════════════════════════

    # -- Connmgr center for reference
    connmgr_cx = dock_x + 100 + comp_w / 2
    connmgr_cy = row1_y + comp_h / 2

    # 1) EDR Agent → Connection Manager: encrypted gRPC (all 3 endpoints)
    for i, ep in enumerate(endpoints):
        agent_left = (ep['x'] + 12, ep['y'] + 8 + 14)
        connmgr_right = (server_x + server_w + 14, connmgr_cy - 12 + i * 12)
        y_off = [-4, 0, 4][i]
        draw_arrow(ax, agent_left, connmgr_right,
                   COLORS['arrow_grpc'],
                   'gRPC (ETW)' if i == 0 else '',
                   fontsize=7, linewidth=1.4,
                   style='<->', offset=(8, 6 + y_off),
                   connectionstyle=f"arc3,rad={-0.08 + i * 0.08}")

    # Add single label for the gRPC channel
    ax.text(362, 230, 'Encrypted gRPC\n(ETW Events &\nResponse Cmds)',
            fontsize=7, color=COLORS['arrow_grpc'], ha='center', va='center',
            fontfamily='Segoe UI', weight='bold', zorder=10,
            path_effects=[pe.withStroke(linewidth=2.5, foreground=COLORS['bg'])],
            bbox=dict(boxstyle='round,pad=0.4', facecolor=COLORS['bg'],
                      edgecolor=COLORS['arrow_grpc'], alpha=0.85, linewidth=0.8))

    # 2) Connection Manager → Kafka: event streaming
    draw_arrow(ax,
               (dock_x + 100 + comp_w / 2, row1_y),
               (dock_x + 100 + comp_w / 2, row2_y + comp_h),
               COLORS['arrow_kafka'],
               'Event\nStreaming', fontsize=6.5, offset=(-20, 0))

    # 3) Kafka → Detection Engine: event consumption
    draw_arrow(ax,
               (dock_x + 100 + comp_w, row2_y + comp_h / 2),
               (dock_x + 192, row1_y),
               COLORS['arrow_kafka'],
               'Event\nConsumption', fontsize=6.5, offset=(4, 6),
               connectionstyle="arc3,rad=-0.3")

    # 4) Detection Engine → Response Engine: alert trigger
    draw_arrow(ax,
               (dock_x + 192, row1_y + comp_h / 2),
               (dock_x + 8 + comp_w, row2_y + comp_h),
               COLORS['arrow_detect'],
               'Alert Trigger', fontsize=6.5, offset=(-2, 6),
               connectionstyle="arc3,rad=0.25")

    # 5) Response Engine → Connection Manager: response commands
    draw_arrow(ax,
               (dock_x + 8 + comp_w, row2_y + comp_h / 2 + 5),
               (dock_x + 100, row1_y),
               COLORS['arrow_response'],
               'Response\nCommands', fontsize=6.5, offset=(-4, 6),
               connectionstyle="arc3,rad=0.3")

    # 6) Dashboard ↔ Backend API
    draw_arrow(ax,
               (dock_x + 8 + comp_w, row1_y + comp_h / 2),
               (dock_x + 100, row1_y + comp_h / 2),
               COLORS['arrow_rest'],
               'REST/WS', fontsize=6.5, style='<->',
               offset=(0, 5))

    # 7) All components → PostgreSQL: data persistence (dashed)
    pg_cx = dock_x + 192 + (comp_w + 5) / 2
    pg_cy = row2_y + comp_h / 2

    # From Dashboard
    draw_arrow(ax,
               (dock_x + 8 + comp_w / 2, row1_y),
               (dock_x + 192 + (comp_w + 5) / 2, row2_y + comp_h),
               COLORS['arrow_db'], '', fontsize=6,
               linewidth=1, linestyle='--',
               connectionstyle="arc3,rad=0.15")

    # From Response Engine
    draw_arrow(ax,
               (dock_x + 8 + comp_w / 2, row2_y),
               (dock_x + 55 + comp_w / 2, row3_y + comp_h),
               COLORS['arrow_db'], '', fontsize=6,
               linewidth=1, linestyle='--',
               connectionstyle="arc3,rad=0.15")

    # PostgreSQL persistence label
    ax.text(dock_x + dock_w - 20, row2_y - 8,
            'Data Persistence (all components)',
            fontsize=6.5, color=COLORS['arrow_db'], ha='right', va='center',
            fontfamily='Segoe UI', style='italic', zorder=10,
            path_effects=[pe.withStroke(linewidth=2, foreground=COLORS['bg'])])

    # ══════════════════════════════════════════════════════════════════════════
    # LEGEND
    # ══════════════════════════════════════════════════════════════════════════
    legend_x, legend_y = 15, -5
    legend_w, legend_h = 495, 40
    legend_bg = FancyBboxPatch(
        (legend_x, legend_y), legend_w, legend_h,
        boxstyle="round,pad=3",
        facecolor=COLORS['legend_bg'], edgecolor=COLORS['legend_border'],
        linewidth=1, alpha=0.92, zorder=8
    )
    ax.add_patch(legend_bg)

    ax.text(legend_x + 10, legend_y + legend_h - 8,
            'LEGEND', fontsize=8, color='#8b949e', weight='bold',
            fontfamily='Segoe UI', zorder=10)

    legend_items = [
        ('--', COLORS['arrow_grpc'], 'Encrypted gRPC'),
        ('--', COLORS['arrow_kafka'], 'Kafka Streaming'),
        ('--', COLORS['arrow_detect'], 'Alert Trigger'),
        ('--', COLORS['arrow_response'], 'Response Cmds'),
        ('--', COLORS['arrow_rest'], 'REST / WebSocket'),
        ('..', COLORS['arrow_db'], 'Data Persistence'),
    ]

    for i, (sym, color, label) in enumerate(legend_items):
        lx = legend_x + 12 + i * 82
        ly = legend_y + 10
        # Draw a small colored line segment instead of text symbol
        ax.plot([lx, lx + 12], [ly, ly], color=color, linewidth=2.5,
                linestyle='-' if sym == '--' else ':', zorder=10)
        ax.text(lx + 15, ly, label, fontsize=7, color=color,
                fontfamily='Segoe UI', weight='bold', zorder=10)

    # ── Port / Protocol annotations ──────────────────────────────────────────
    ax.text(server_x + server_w + 16, server_y + server_h + 8,
            'Server: 0.0.0.0  |  Ports: 30088 (HTTP), 50051 (gRPC), 5432, 9092, 6379',
            fontsize=7, color='#6e7681', fontfamily='Segoe UI', zorder=10,
            path_effects=[pe.withStroke(linewidth=2, foreground=COLORS['bg'])])

    # ══════════════════════════════════════════════════════════════════════════
    # SAVE
    # ══════════════════════════════════════════════════════════════════════════
    output_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(output_dir, 'edr_deployment_diagram.png')

    plt.tight_layout(pad=0.5)
    fig.savefig(output_path, dpi=250, bbox_inches='tight',
                facecolor=COLORS['bg'], edgecolor='none',
                pad_inches=0.3)
    plt.close(fig)
    res_w = fig.get_size_inches()[0] * 250
    res_h = fig.get_size_inches()[1] * 250
    print(f'Diagram saved to: {output_path}')
    print(f'Resolution: {res_w:.0f} x {res_h:.0f} px')


if __name__ == '__main__':
    main()
