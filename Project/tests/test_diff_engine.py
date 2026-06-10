import sys
from pathlib import Path

# Add project root to python path to access backend logic
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.append(str(PROJECT_ROOT))

from backend.app.diff import generate_config_diff

def test_generate_config_diff_basic():
    old_content = """interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
 shutdown
!"""
    new_content = """interface GigabitEthernet0/1
 ip address 192.168.1.1 255.255.255.0
 no shutdown
 description Management Interface
!"""

    res = generate_config_diff(old_content, new_content)
    
    # Assert counts
    # 'shutdown' replaced by 'no shutdown' -> 1 modified line
    # 'description Management Interface' is added -> 1 added line
    assert res["added_count"] == 1
    assert res["modified_count"] == 1
    assert res["removed_count"] == 0
    
    # Check lines list structure
    lines = res["diff_json"]["lines"]
    assert len(lines) > 0
    
    # Ensure types exist
    types = [line["type"] for line in lines]
    assert "modified" in types
    assert "added" in types
    assert "unchanged" in types
    
    # Check statistics
    stats = res["diff_json"]["statistics"]
    assert stats["added"] == 1
    assert stats["modified"] == 1
    assert stats["removed"] == 0
    assert stats["total_old"] == 4
    assert stats["total_new"] == 5
