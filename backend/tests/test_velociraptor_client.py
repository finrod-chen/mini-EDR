from unittest.mock import patch

from app.services import velociraptor_client


def test_query_converts_columns_to_rows() -> None:
    columns = {
        "client_id": ["C.1111", "C.2222"],
        "hostname": ["PC-01", "PC-02"],
    }
    with patch.object(velociraptor_client.velo_pandas, "DataFrameQuery", return_value=columns):
        rows = velociraptor_client.query("SELECT * FROM clients()", config={})

    assert rows == [
        {"client_id": "C.1111", "hostname": "PC-01"},
        {"client_id": "C.2222", "hostname": "PC-02"},
    ]


def test_query_returns_empty_list_when_no_results() -> None:
    with patch.object(velociraptor_client.velo_pandas, "DataFrameQuery", return_value={}):
        rows = velociraptor_client.query("SELECT * FROM clients()", config={})

    assert rows == []
