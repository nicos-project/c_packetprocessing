import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import random
def parse_mem_dump(file_path):
    times = []
    file = open(file_path)
    for line in file:
        time_strs = line.split()
        
        if len(time_strs) < 5:
            break

        times.append(int(time_strs[1], 16))
        times.append(int(time_strs[2], 16))
        times.append(int(time_strs[3], 16))
        times.append(int(time_strs[4], 16))
    return times

def graph_write_times():
    ctm32_write_times = pd.Series(parse_mem_dump("ctm32_write_times.txt")).iloc[0:100]#.multiply(16 * 1.25)
    ctm33_write_times = pd.Series(parse_mem_dump("ctm33_write_times.txt")).iloc[0:100]#.multiply(16 * 1.25)
    ctm34_write_times = pd.Series(parse_mem_dump("ctm34_write_times.txt")).iloc[0:100]#.multiply(16 * 1.25)
    ctm35_write_times = pd.Series(parse_mem_dump("ctm35_write_times.txt")).iloc[0:100]#.multiply(16 * 1.25)
    ctm36_write_times = pd.Series(parse_mem_dump("ctm36_write_times.txt")).iloc[0:100]#.multiply(16 * 1.25)

    imem_write_times = pd.Series(parse_mem_dump("imem_write_times.txt")).iloc[0:100]#.multiply(16 * 1.25)
    emem0_write_times = pd.Series(parse_mem_dump("emem0_write_times.txt")).iloc[0:100]#.multiply(16 * 1.25)
    emem1_write_times = pd.Series(parse_mem_dump("emem1_write_times.txt")).iloc[0:100]#.multiply(16 * 1.25)
    emem0_cache_write_times = pd.Series(parse_mem_dump("emem0.cache_write_times.txt")).iloc[0:100]#.multiply(16 * 1.25)
    emem1_cache_write_times = pd.Series(parse_mem_dump("emem1.cache_write_times.txt")).iloc[0:100]#.multiply(16 * 1.25)

    data = {"ctm32": ctm32_write_times, 
            "ctm33": ctm33_write_times,
            "ctm34": ctm34_write_times,
            "ctm35": ctm35_write_times,
            "ctm36": ctm36_write_times,
            "imem": imem_write_times,
            "emem0": emem0_write_times,
            "emem1": emem1_write_times,
            "emem0.cache": emem0_cache_write_times,
            "emem1.cache": emem1_cache_write_times}

    df = pd.DataFrame(data=data)
    g = df.plot(kind="line", xlabel="Address", ylabel="Latency (16-cycle counter)").get_figure()
    g.savefig("i32_write_latency.pdf")

def graph_read_times():
    ctm32_read_times = pd.Series(parse_mem_dump("ctm32_read_times.txt")).add(random.uniform(-.1, .1)).iloc[0:100]#.multiply(16 * 1.25)
    ctm33_read_times = pd.Series(parse_mem_dump("ctm33_read_times.txt")).add(random.uniform(-.1, .1)).iloc[0:100]#.multiply(16 * 1.25)
    ctm34_read_times = pd.Series(parse_mem_dump("ctm34_read_times.txt")).add(random.uniform(-.1, .1)).iloc[0:100]#.multiply(16 * 1.25)
    ctm35_read_times = pd.Series(parse_mem_dump("ctm35_read_times.txt")).add(random.uniform(-.1, .1)).iloc[0:100]#.multiply(16 * 1.25)
    ctm36_read_times = pd.Series(parse_mem_dump("ctm36_read_times.txt")).add(random.uniform(-.1, .1)).iloc[0:100]#.multiply(16 * 1.25)

    imem_read_times = pd.Series(parse_mem_dump("imem_read_times.txt")).add(random.uniform(-.1, .1)).iloc[0:100]#.multiply(16 * 1.25)
    emem0_read_times = pd.Series(parse_mem_dump("emem0_read_times.txt")).add(random.uniform(-.1, .1)).iloc[0:100]#.multiply(16 * 1.25)
    emem1_read_times = pd.Series(parse_mem_dump("emem1_read_times.txt")).add(random.uniform(-.1, .1)).iloc[0:100]#.multiply(16 * 1.25)
    emem0_cache_read_times = pd.Series(parse_mem_dump("emem0.cache_read_times.txt")).add(random.uniform(-.1, .1)).iloc[0:100]#.multiply(16 * 1.25)
    emem1_cache_read_times = pd.Series(parse_mem_dump("emem1.cache_read_times.txt")).add(random.uniform(-.1, .1)).iloc[0:100]#.multiply(16 * 1.25)

    data = {"ctm32": ctm32_read_times, 
            "ctm33": ctm33_read_times,
            "ctm34": ctm34_read_times,
            "ctm35": ctm35_read_times,
            "ctm36": ctm36_read_times,
            "imem": imem_read_times,
            "emem0": emem0_read_times,
            "emem1": emem1_read_times,
            "emem0.cache": emem0_cache_read_times,
            "emem1.cache": emem1_cache_read_times}

    df = pd.DataFrame(data=data)
    g = df.plot(kind="line", xlabel="Address", ylabel="Latency (16-cycle counter)").get_figure()
    g.savefig("i32_read_latency.pdf")

def graph_op_times(graph_title, path, op_name):
    ctm32_times = pd.Series(parse_mem_dump(path + "/ctm32_" + op_name + "_times.txt")).iloc[0:1000]#.multiply(16 * 1.25)
    ctm33_times = pd.Series(parse_mem_dump(path + "/ctm33_" + op_name + "_times.txt")).iloc[0:1000]#.multiply(16 * 1.25)
    ctm34_times = pd.Series(parse_mem_dump(path + "/ctm34_" + op_name + "_times.txt")).iloc[0:1000]#.multiply(16 * 1.25)
    ctm35_times = pd.Series(parse_mem_dump(path + "/ctm35_" + op_name + "_times.txt")).iloc[0:1000]#.multiply(16 * 1.25)
    ctm36_times = pd.Series(parse_mem_dump(path + "/ctm36_" + op_name + "_times.txt")).iloc[0:1000]#.multiply(16 * 1.25)

    imem_times = pd.Series(parse_mem_dump(path + "/imem_" + op_name + "_times.txt")).iloc[0:1000]#.multiply(16 * 1.25)
    emem0_times = pd.Series(parse_mem_dump(path + "/emem0_" + op_name + "_times.txt")).iloc[0:1000]#.multiply(16 * 1.25)
    emem1_times = pd.Series(parse_mem_dump(path + "/emem1_" + op_name + "_times.txt")).iloc[0:1000]#.multiply(16 * 1.25)
    emem0_cache_times = pd.Series(parse_mem_dump(path + "/emem0.cache_"+ op_name +"_times.txt")).iloc[0:1000]#.multiply(16 * 1.25)
    emem1_cache_times = pd.Series(parse_mem_dump(path + "/emem1.cache_"+ op_name +"_times.txt")).iloc[0:1000]#.multiply(16 * 1.25)

    data = {"ctm32": ctm32_times, 
            "ctm33": ctm33_times,
            "ctm34": ctm34_times,
            "ctm35": ctm35_times,
            "ctm36": ctm36_times,
            "imem": imem_times,
            "emem0": emem0_times,
            "emem1": emem1_times,
            "emem0.cache": emem0_cache_times,
            "emem1.cache": emem1_cache_times}

    df = pd.DataFrame(data=data)

    # Define custom styles and colors for each line
    styles = {
        "ctm32": {"color": "blue", "linestyle": "-", "marker": "o", "linewidth": 2},
        "ctm33": {"color": "green", "linestyle": "--", "marker": "s", "linewidth": 2},
        "ctm34": {"color": "red", "linestyle": "-.", "marker": "^", "linewidth": 2},
        "ctm35": {"color": "purple", "linestyle": ":", "marker": "d", "linewidth": 2},
        "ctm36": {"color": "orange", "linestyle": "-", "marker": "x", "linewidth": 2},
        "imem": {"color": "brown", "linestyle": "--", "marker": "+", "linewidth": 2},
        "emem0": {"color": "gold", "linestyle": "-.", "marker": "v", "linewidth": 2},
        "emem1": {"color": "black", "linestyle": "solid", "marker": "<", "linewidth": 2},
        "emem0.cache": {"color": "cyan", "linestyle": "-", "marker": ">", "linewidth": 2},
        "emem1.cache": {"color": "magenta", "linestyle": "dotted", "marker": "*", "linewidth": 2}
    }
    # Create figure and axis objects explicitly
    fig, ax = plt.subplots(figsize=(12, 8))
    # Plot each column with custom style
    for column in df.columns:
        ax.plot(df.index, df[column],
                color=styles[column]["color"],
                linestyle=styles[column]["linestyle"],
                marker=styles[column]["marker"],
                linewidth=styles[column]["linewidth"],
                markersize=2,
                markevery=10,  # Add markers every 10 points to avoid overcrowding
                alpha=0.7,
                label=column)
    # Add labels and legend
    ax.set_xlabel("Address")
    ax.set_ylabel("Latency (cycles)")
    ax.set_title(graph_title)
    ax.legend(loc="best")
    ax.grid(True, linestyle="--", alpha=0.7)
    # Save figure
    fig.savefig(graph_title + ".pdf", bbox_inches="tight")
    plt.close(fig)

graph_op_times("i36_write_latency", "time/cycle/i36.me0", "write")
graph_op_times("i36_read_latency", "time/cycle/i36.me0", "read")
graph_op_times("i36_wr_latency", "time/cycle/i36.me0", "wr")