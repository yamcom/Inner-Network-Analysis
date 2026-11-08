from __future__ import annotations

from unittest.mock import patch
from dhcp_monitor import resolve_windows_interface


def test_resolve_windows_interface_matches_friendly_chinese_name():
    mock_if_list = [
        {
            "name": "乙太網路 2",
            "description": "Intel(R) Ethernet Connection (11) I219-LM",
            "guid": "{73456D91-2551-4F14-AA3E-F8C558D08E01}",
        },
        {
            "name": "區域連線* 6",
            "description": "WAN Miniport (IP)",
            "guid": "{52E6BC0E-5701-44C1-9262-B03D8833BF55}",
        },
    ]

    with patch("scapy.arch.windows.get_windows_if_list", return_value=mock_if_list):
        # 1. 中文友善名稱比對
        dev1 = resolve_windows_interface("乙太網路 2")
        assert dev1 == "\\Device\\NPF_{73456D91-2551-4F14-AA3E-F8C558D08E01}"

        # 2. 說明欄位比對 (不分大小寫)
        dev2 = resolve_windows_interface("intel(r) ethernet connection (11) i219-lm")
        assert dev2 == "\\Device\\NPF_{73456D91-2551-4F14-AA3E-F8C558D08E01}"

        # 3. GUID 比對
        dev3 = resolve_windows_interface("{52E6BC0E-5701-44C1-9262-B03D8833BF55}")
        assert dev3 == "\\Device\\NPF_{52E6BC0E-5701-44C1-9262-B03D8833BF55}"

        # 4. 未提供或空值
        assert resolve_windows_interface(None) is None
        assert resolve_windows_interface("") is None

        # 5. 不存在的介面保持原樣
        assert resolve_windows_interface("non-existent-nic") == "non-existent-nic"
