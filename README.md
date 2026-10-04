# 水库防汛调度与操作确认

根据库位、入库流量、下游警戒和施工限制生成复核授权的泄洪指令。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制和审计链。
- `src/service.py`：权限检查、用例编排、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则和失败测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8315
```

默认端口为`8315`，首次启动自动建库。使用`X-Actor`和`X-Role`请求头传递身份。

## 主要接口

- `GET /health`
- `GET /api/items`
- `POST /api/items`
- `GET /api/items/{id}`
- `POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `GET /api/audit`
- `GET /api/repair-batches`
- `GET /api/repair-batches/{batch_no}`
- `POST /api/repair-batches`
- `POST /api/repair-batches/{batch_no}/confirm`
- `POST /api/repair-batches/{batch_no}/apply`

允许角色：duty_officer, chief_engineer, dispatcher, discipline_inspector, viewer。库位超过汛限或入库流量上升时提升紧迫度；授权前必须有复核记录，执行后仍要闭环现场反馈。

## 审计链修复批次

1. 值班员、总工或纪检可按 `batch_no` 开启批次：系统定位首个审计链断点，把断点及其后的事件完整复制到隔离表，并从活动审计链移除；断点前事件不改。
2. 总工（`chief_engineer`）和纪检（`discipline_inspector`）分别调用确认接口。双方确认前只能得到 `open` 批次；双方确认后变为 `ready`。
3. 批次范围内指令仅暂停关闭，新增记录、复核、授权、执行以及范围外指令均照常。
4. `ready` 后按批次号提交修复：追加 `repair_begin` 标记续写点和原最后有效哈希，仅接回自身哈希未损坏的隔离事件（事件内容和时间保持原样），再追加 `repair_complete`；损坏事件保留在隔离表。
5. 修复写入在单个事务内完成；失败回滚，可用同一 `batch_no` 重试。两个并发提交只有一个生效，后到者收到409和 `repair_batch_gap`。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
