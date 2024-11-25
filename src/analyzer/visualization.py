# Standard library imports
import os
import json
import logging
from typing import Dict, List, Tuple
from datetime import datetime

# Third-party imports
import numpy as np
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.colors as mcolors
import matplotlib.patches as mpatches

# Configure logger
logger = logging.getLogger(__name__)

def visualize_network_overview(G1: nx.Graph, G2: nx.Graph, output_folder: str) -> None:
    """Create network visualization comparing two snapshots"""
    os.makedirs(output_folder, exist_ok=True)
    
    fig, axs = plt.subplots(2, 2, figsize=(20, 15))
    
    # Plot degree distributions
    degrees1 = [d for n, d in G1.degree()]
    degrees2 = [d for n, d in G2.degree()]
    
    degrees1 = [np.nan if np.isinf(d) else d for d in degrees1]
    degrees2 = [np.nan if np.isinf(d) else d for d in degrees2]
    
    sns.histplot(degrees1, color='blue', label='Before', kde=False, stat="density", bins=20, alpha=0.5, ax=axs[0,0])
    sns.histplot(degrees2, color='green', label='After', kde=False, stat="density", bins=20, alpha=0.5, ax=axs[0,0])
    axs[0,0].set_title('Degree Distribution Comparison')
    axs[0,0].set_xlabel('Degree')
    axs[0,0].set_ylabel('Density')
    axs[0,0].legend()
    
    # Plot network layouts
    pos_before = nx.spring_layout(G1, seed=42)
    nx.draw(G1, pos_before, node_size=50, alpha=0.6, with_labels=False, node_color='blue', ax=axs[0,1])
    axs[0,1].set_title('Network Before')
    
    pos_after = nx.spring_layout(G2, seed=42)
    nx.draw(G2, pos_after, node_size=50, alpha=0.6, with_labels=False, node_color='green', ax=axs[1,0])
    axs[1,0].set_title('Network After')
    
    # Add metrics comparison
    axs[1,1].axis('off')
    metrics_text = (
        f"Network Metrics Comparison:\n\n"
        f"Before:\n"
        f"Nodes: {G1.number_of_nodes()}\n"
        f"Edges: {G1.number_of_edges()}\n"
        f"Density: {nx.density(G1):.3f}\n\n"
        f"After:\n"
        f"Nodes: {G2.number_of_nodes()}\n"
        f"Edges: {G2.number_of_edges()}\n"
        f"Density: {nx.density(G2):.3f}"
    )
    axs[1,1].text(0.1, 0.5, metrics_text, fontsize=12, va='center')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_folder, 'network_overview.png'))
    plt.close()

def visualize_critical_infrastructure(G: nx.Graph, bridge_nodes: List, critical_paths: Dict, output_folder: str) -> None:
    """Create visualization highlighting critical infrastructure"""
    plt.figure(figsize=(15, 10))
    
    # Create layout
    pos = nx.spring_layout(G, k=1, iterations=50)
    
    # Draw base network
    nx.draw_networkx_edges(G, pos, alpha=0.2, edge_color='gray')
    
    # Draw nodes with size based on importance
    node_colors = []
    node_sizes = []
    bridge_nodes_set = {node for node, _ in bridge_nodes}
    
    for node in G.nodes():
        if node in bridge_nodes_set:
            node_colors.append('red')
            node_sizes.append(300)
        else:
            node_colors.append('lightblue')
            node_sizes.append(100)
    
    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes)
    
    # Highlight critical paths
    for path in list(critical_paths.values())[:3]:  # Top 3 critical paths
        path_edges = list(zip(path[:-1], path[1:]))
        nx.draw_networkx_edges(G, pos, edgelist=path_edges, edge_color='red', width=2)
    
    # Add legend
    legend_elements = [
        mpatches.Patch(color='red', label='Bridge Nodes'),
        mpatches.Patch(color='lightblue', label='Regular Nodes'),
        mpatches.Patch(color='red', alpha=0.5, label='Critical Paths')
    ]
    plt.legend(handles=legend_elements, loc='upper left', bbox_to_anchor=(1, 1))
    
    plt.title("Critical Infrastructure Analysis")
    plt.tight_layout()
    plt.savefig(os.path.join(output_folder, 'critical_infrastructure.png'))
    plt.close()

def visualize_node_metrics_heatmap(centrality_changes: pd.DataFrame, output_folder: str) -> None:
    """Create heatmap of changes in node metrics"""
    plt.figure(figsize=(12, 16))
    
    sns.heatmap(centrality_changes, 
                annot=True,
                cmap='coolwarm',
                center=0,
                fmt='.3f',
                cbar_kws={'label': 'Change in Centrality'},
                square=False,
                linewidths=0.5)
    
    plt.title('Changes in Centrality Measures for All Nodes', pad=20)
    plt.xlabel('Centrality Metrics', labelpad=10)
    plt.ylabel('Nodes', labelpad=10)
    
    plt.xticks(rotation=45, ha='right')
    plt.yticks(rotation=0)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_folder, 'node_metrics_changes_heatmap.png'))
    plt.close()

def create_markdown_report(before_data: Dict, after_data: Dict, changes: Dict, 
                         metrics_before: Dict, metrics_after: Dict,
                         critical_paths: Dict, bridge_nodes: List,
                         segmentation: Dict, output_folder: str) -> None:
    """Create a comprehensive markdown report with analysis results"""
    report_path = os.path.join(output_folder, 'network_analysis_report.md')
    
    with open(report_path, 'w') as f:
        # Header
        f.write("# Network Analysis Report\n\n")
        f.write(f"Generated on: {datetime.now().isoformat()}\n\n")
        
        # Network Overview
        f.write("## Network Overview\n\n")
        f.write("![Network Overview](network_overview.png)\n\n")
        
        # Structural Changes
        f.write("## Structural Changes\n\n")
        f.write("| Change Type | Value |\n")
        f.write("|-------------|-------|\n")
        for change_type, value in changes.items():
            f.write(f"| {change_type.replace('_', ' ')} | {value} |\n")
        f.write("\n")
        
        # Network Metrics Comparison
        f.write("## Network Metrics Comparison\n\n")
        f.write("| Metric | Before | After | Change |\n")
        f.write("|--------|---------|--------|--------|\n")
        for metric in metrics_before.keys():
            before_val = metrics_before[metric]
            after_val = metrics_after[metric]
            change = after_val - before_val
            f.write(f"| {metric.replace('_', ' ')} | {before_val:.3f} | {after_val:.3f} | {change:+.3f} |\n")
        f.write("\n")
        
        # Critical Infrastructure
        f.write("## Critical Infrastructure Analysis\n\n")
        f.write("![Critical Infrastructure](critical_infrastructure.png)\n\n")
        
        # Bridge Nodes
        f.write("### Bridge Nodes\n\n")
        f.write("| Node | Impact |\n")
        f.write("|------|--------|\n")
        for node, impact in bridge_nodes[:5]:  # Top 5 bridge nodes
            f.write(f"| {node} | Splits into {impact} components |\n")
        f.write("\n")
        
        # Critical Paths
        f.write("### Critical Paths\n\n")
        f.write("| Path | Length |\n")
        f.write("|------|--------|\n")
        for path_name, path in list(critical_paths.items())[:5]:  # Top 5 critical paths
            f.write(f"| {' -> '.join(path)} | {len(path)} |\n")
        f.write("\n")
        
        # Network Segmentation
        f.write("## Network Segmentation\n\n")
        f.write(f"- Number of Segments: {segmentation['num_segments']}\n")
        f.write(f"- Modularity Score: {segmentation['modularity']:.3f}\n")
        f.write(f"- Cross-Segment Connections: {segmentation['cross_segment_edges']}\n")
        f.write(f"- Isolation Score: {segmentation['isolation_score']:.3f}\n\n")
        
        # Node Metrics Changes
        f.write("## Node Metrics Changes\n\n")
        f.write("![Node Metrics Changes](node_metrics_changes_heatmap.png)\n\n")
        
        # Recommendations
        f.write("## Recommendations\n\n")
        if changes['New_Nodes'] > 0 or changes['New_Edges'] > 0:
            f.write("1. Review new network connections for unauthorized changes\n")
        if len(bridge_nodes) > 0:
            f.write("2. Implement redundancy for critical bridge nodes\n")
        if segmentation['cross_segment_edges'] > 0:
            f.write("3. Review and strengthen network segmentation\n")
        if len(critical_paths) > 0:
            f.write("4. Monitor critical paths for potential attack vectors\n") 