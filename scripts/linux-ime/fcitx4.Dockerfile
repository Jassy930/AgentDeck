# fcitx4（搜狗输入法 Linux 版的底座）无头回归镜像，配合 x11.sh fcitx4 使用。
# 构建：docker build -t agentdeck-ime-fcitx4 -f scripts/linux-ime/fcitx4.Dockerfile scripts/linux-ime
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i "s#http://archive.ubuntu.com#http://cn.archive.ubuntu.com#g; s#http://security.ubuntu.com#http://cn.archive.ubuntu.com#g" \
      /etc/apt/sources.list.d/ubuntu.sources && \
    apt-get update && apt-get install -y --no-install-recommends \
      xvfb xdotool imagemagick mesa-vulkan-drivers libvulkan1 dbus dbus-x11 locales fonts-noto-cjk \
      libxkbcommon-x11-0 libxcb1 libxcb-xkb1 libfontconfig1 \
      fcitx fcitx-pinyin fcitx-frontend-all fcitx-module-x11 fcitx-config-gtk procps && \
    locale-gen zh_CN.UTF-8 en_US.UTF-8 && rm -rf /var/lib/apt/lists/*
