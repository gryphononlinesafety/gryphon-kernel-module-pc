# Gryphon Kernel Module PC

![Gryphon Connect][(https://gryphonconnect.com/))

Welcome to the **Gryphon Kernel Module PC** repository! This repository contains a Linux kernel module developed by **[Gryphon Connect](https://gryphonconnect.com/)** to work with Gryphon Software

## 📌 Overview

This project provides a kernel module to work with Gryphon Software

## 🔧 Features

- ✅ **Real-Time Monitoring** – Logs and processes network activity directly in the kernel space.
- ✅ **Custom Netfilter Hooks** – Allows flexible packet filtering and modification.

## ⚙️ Compatibility & Requirements

The **Gryphon Kernel Module PC** is tested and compatible with:

- **OpenWRT versions:** 16.04, 19.04, 21.02, 22.03, and latest master branch
- **Kernel versions:** 4.4, 5.4, 5.10, 5.15, and 6.x
- **Supported Architectures:** x86_64, ARM, AARCH64

Before installing, ensure your OpenWRT system has:
- **Kernel headers installed** (`kmod-compat`, `kmod-netfilter` dependencies)
- **GCC toolchain** for custom module compilation

## 🚀 Installation Guide

Clone the repository into standard OpenWRT framework and enable the package via "make menuconfig" and compile

## Customisation and Compilation Flags
- ENABLE_GRY_MARK compilation flag is used to enabling the marking of the packets via CFLAGS, enable or disable via Makefile
- GRY_MARK_VALUE in the gryphon_dpi.c file is used to mark the skb with value 0x09, if you want to customise this to your platform change it to a valid hex value

