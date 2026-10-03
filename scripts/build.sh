#!/bin/bash
# binmind Docker build script
set -e

# -- 全局配置
# 全局构建配置
g_docker_image="binmind:latest"
g_network_name="binmind-network"
g_build_retries=2  # docker build重试次数，网络差的时候有用

# -- _say
# 打印带前缀的进度消息
_say() {
    echo "[binmind-build] $*"
}

# -- build_image
# 构建Docker镜像，带重试
build_image() {
    local _try=0
    local _max=$g_build_retries

    _say "开始构建Docker镜像: $g_docker_image"

    while [ $_try -le $_max ]; do
        _try=$((_try + 1))
        if docker build -t "$g_docker_image" . 2>&1; then
            _say "镜像构建成功"
            return 0
        fi
        # apt-get update在docker build里经常因为网络超时
        # 不加重试的话用户体验太差, 每次都要手动重跑
        if [ $_try -le $_max ]; then
            _say "构建失败，${_try}/${_max}次重试..."
            sleep 3
        fi
    done

    _say "错误: 镜像构建失败，已重试${_max}次"
    return 1
}

# -- check_prereqs
# 前置检查, pyproject.toml必须在，不然docker build找不到依赖
check_prereqs() {
    if [ ! -f "pyproject.toml" ]; then
        echo "错误: pyproject.toml未找到，请在项目根目录运行。" >&2
        echo "  cd /path/to/binmind && bash scripts/build.sh" >&2
        return 1
    fi
    return 0
}

# -- setup_dirs
# 创建工作目录, 这些目录在docker-compose里mount的
setup_dirs() {
    _say "创建工作目录..."
    # 目录如果已存在mkdir -p不会报错，不用先检测
    mkdir -p workspace data reports
}

# -- setup_network
# 创建Docker网络, 已存在就跳过
# docker network create重复创建返回非零但不影响使用
# 所以用 || true 吞掉错误
setup_network() {
    _say "创建Docker网络: $g_network_name"
    if docker network ls --format '{{.Name}}' 2>/dev/null | grep -qx "$g_network_name"; then
        _say "网络已存在，跳过"
        return 0
    fi
    docker network create "$g_network_name" 2>/dev/null || true
}

# -- start_services
# 启动docker-compose服务
start_services() {
    _say "启动服务..."
    if ! docker-compose up -d 2>&1; then
        echo "错误: docker-compose up失败" >&2
        echo "  检查docker是否在运行: docker ps" >&2
        return 1
    fi
}

# -- print_info
# 打印安装后的使用说明
print_info() {
    echo ""
    echo "=== BinMind环境已启动 ==="
    echo ""
    echo "进入分析容器:"
    echo "  docker exec -it binmind-analysis /bin/bash"
    echo ""
    echo "运行CLI:"
    echo "  docker exec -it binmind-analysis python -m modules.cli --help"
    echo ""
    echo "工作目录: ./workspace (宿主机)"
    echo "报告目录: ./reports (宿主机)"
    echo ""
    echo "查看日志:"
    echo "  docker-compose logs -f"
    echo ""
}

# ============================================================
# main ,  构建主流程
# ============================================================

echo "=== BinMind构建脚本 ==="
echo ""

check_prereqs || exit 1
setup_dirs
build_image || {
    echo "警告: 镜像构建有问题，但继续尝试启动..." >&2
}
setup_network
start_services || exit 1
print_info
