### doca_netflow

```
meson setup build
```

```
ninja -C build
```

```
sudo ~/netflow/doca_netflow/simple_fwd_vnf/build/doca_netflow_app -a auxiliary:mlx5_core.sf.4,dv_flow_en=2 -a auxiliary:mlx5_core.sf.5,dv_flow_en=2 -- -l 60 -q 8
```
