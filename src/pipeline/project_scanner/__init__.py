import sys
import ctypes
from pathlib import WindowsPath

# --- MONKEY PATCH SỬA LỖI WINDOWSPATH CỦA PYCUBOOL ---
# Ép kiểu tất cả các đường dẫn WindowsPath truyền vào ctypes thành chuỗi (str)
original_load_library = ctypes.cdll.LoadLibrary
def patched_load_library(name):
    if isinstance(name, WindowsPath):
        name = str(name)
    return original_load_library(name)
ctypes.cdll.LoadLibrary = patched_load_library
# ---------------------------------------------------

import json
import os
import time
import pycubool as cb
from loguru import logger
from log_controller import setup_logger


def load_json_graph(input_json_path):
    """
    Đọc file JSON đầu vào và xây dựng danh sách ánh xạ (bi-directional mapping)
    giữa chuỗi (tên node) và số nguyên (chỉ mục ma trận).
    """
    logger.info(f"Đang đọc file đầu vào JSON từ: {input_json_path}")
    with open(input_json_path, 'r', encoding='utf-8') as f:
        graph_data = json.load(f)

    # Thu thập tất cả các node xuất hiện trong đồ thị để đánh chỉ mục vuông
    all_nodes = set()
    for source, targets in graph_data.items():
        all_nodes.add(source)
        for target in targets:
            all_nodes.add(target)

    node_to_idx = {node: idx for idx, node in enumerate(sorted(all_nodes))}
    idx_to_node = {idx: node for node, idx in node_to_idx.items()}
    
    # Chuyển đổi các cạnh sang dạng số nguyên
    edges = []
    for source, targets in graph_data.items():
        u = node_to_idx[source]
        for target in targets:
            v = node_to_idx[target]
            edges.append((u, v))
            
    return edges, node_to_idx, idx_to_node, len(all_nodes)


def generate_matrix_fast(edges, num_nodes):
    """
    Sử dụng mảng NumPy để gom toàn bộ danh sách tọa độ hàng/cột,
    giúp khởi tạo ma trận pycubool cực nhanh thay vì gán thủ công từng phần tử.
    """
    if num_nodes == 0:
        return cb.Matrix.empty(shape=(0, 0))
        
    logger.info(f"Khởi tạo ma trận kích thước: {num_nodes}x{num_nodes} với {len(edges)} cạnh ban đầu.")
    
    if not edges:
        return cb.Matrix.empty(shape=(num_nodes, num_nodes))

    # Tách danh sách cạnh thành 2 mảng hàng (rows) và cột (cols)
    import numpy as np
    edges_arr = np.array(edges, dtype=np.int32)
    rows = edges_arr[:, 0].tolist()
    cols = edges_arr[:, 1].tolist()

    # Nạp trực tiếp dữ liệu dạng danh sách tọa độ vào pycubool (Bulk loading)
    bool_matrix = cb.Matrix.from_lists(shape=(num_nodes, num_nodes), rows=rows, cols=cols)
    return bool_matrix


def calculate_transitive_closure(matrix):
    """
    Giữ nguyên thuật toán nhân ma trận bình phương (Squaring method) gốc của bạn
    để tìm bao đóng chuyển tiếp bằng pycubool.
    """
    logger.info("Bắt đầu quá trình nhân ma trận tính Reachable Graph...")
    total = -1
    i = 0
    start_time = time.time()
    
    while total != matrix.nvals:
        total = matrix.nvals
        # t += t * t
        matrix.mxm(matrix, out=matrix, accumulate=True)  
        i += 1
        
    end_time = time.time()
    logger.info(f"Hoàn thành nhân ma trận. Số vòng lặp: {i}, Thời gian tính toán: {end_time - start_time:.4f}s")
    return matrix


def save_matrix_to_json(matrix, idx_to_node, output_json_path):
    """
    Xuất ma trận kề của pycubool sau khi nhân thành file JSON theo đúng định dạng yêu cầu.
    """
    logger.info(f"Đang xuất kết quả Transitive Closure ra file JSON: {output_json_path}")
    start_time = time.time()
    
    # Lấy toàn bộ các cặp tọa độ True trong ma trận
    rows, cols = matrix.to_lists()
    
    # Tạo cấu trúc danh sách kề kết quả
    result_graph = {node: [] for node in idx_to_node.values()}
    
    for r, c in zip(rows, cols):
        source_node = idx_to_node[r]
        target_node = idx_to_node[c]
        result_graph[source_node].append(target_node)
        
    # Loại bỏ các node không có cạnh đi ra nếu muốn file JSON gọn nhẹ, 
    # hoặc giữ nguyên để đảm bảo đủ key. Ở đây giữ nguyên cấu trúc chuẩn.
    result_graph = {k: sorted(v) for k, v in result_graph.items() if v}

    with open(output_json_path, 'w', encoding='utf-8') as f:
        json.dump(result_graph, f, ensure_ascii=False, indent=4)
        
    logger.info(f"Lưu file hoàn tất! Thời gian export: {time.time() - start_time:.4f}s")


def process_pipeline(input_json_path, output_json_path):
    start_total = time.time()
    
    # 1. Đọc dữ liệu JSON & Ánh xạ ID
    edges, node_to_idx, idx_to_node, num_nodes = load_json_graph(input_json_path)
    
    if num_nodes == 0:
        logger.warning("Đồ thị trống, tạo file JSON đầu ra rỗng.")
        with open(output_json_path, 'w') as f:
            json.dump({}, f)
        return

    # 2. Tạo ma trận tốc độ cao qua NumPy chuyển đổi sang PyCubool
    matrix = generate_matrix_fast(edges, num_nodes)
    
    # 3. Tính bao đóng chuyển tiếp (Transitive Closure)
    matrix = calculate_transitive_closure(matrix)
    
    # 4. Lưu kết quả ra file JSON mới
    save_matrix_to_json(matrix, idx_to_node, output_json_path)
    
    logger.info(f"Tổng thời gian xử lý toàn bộ pipeline: {time.time() - start_total:.4f}s")


if __name__ == '__main__':
    script_name = os.path.splitext(os.path.basename(__file__))[0]
    setup_logger(script_name)
    
    # Cấu hình đường dẫn file thực tế của bạn tại đây
    input_path = "E:\\demo dự án\\path.json"
    output_path = "E:\\demo dự án\\output_reachable_graph.json"
    
    # Thực thi pipeline chuyên đổi
    process_pipeline(input_path, output_path)