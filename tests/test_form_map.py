"""Deterministic tests for the authenticated form-map parser.

The authenticated fetch itself is network-bound (and tested implicitly via the
webvuln workflow tests); here we lock down the HTML→FormSpec parser and the
summariser the LLM planner consumes, so a regex regression can't silently drop
the signal that unlocks dynamic sink detection.
"""
from __future__ import annotations

from vapt_agents.form_map import (
    EndpointMap, FormSpec, _parse_forms, summarize_for_llm,
)


def test_parse_single_textarea_form():
    html = (
        '<form method="post" action="/admin/offer">'
        '  <textarea name="offer" rows="2">prev</textarea>'
        '  <input type="hidden" name="csrf_token" value="abc">'
        '</form>'
    )
    forms = _parse_forms(html, "http://host:5000/admin/offer")
    assert len(forms) == 1
    f = forms[0]
    assert f.method == "post"
    assert f.action.endswith("/admin/offer")
    names = f.field_names()
    assert "offer" in names and "csrf_token" in names
    types = {x.name: x.type for x in f.fields}
    assert types["offer"] == "textarea"
    assert types["csrf_token"] == "hidden"


def test_parse_mixed_fields_and_select():
    html = (
        '<form method="POST" action="/feedback/submit">'
        '  <input type="text" name="name">'
        '  <input type="email" name="email" value="a@b.c">'
        '  <input type="number" name="rating">'
        '  <select name="restaurant_id"><option>1</option></select>'
        '  <textarea name="message"></textarea>'
        '</form>'
    )
    forms = _parse_forms(html, "http://host:5000/feedback")
    assert len(forms) == 1
    f = forms[0]
    assert f.method == "post"
    types = {x.name: x.type for x in f.fields}
    assert types == {
        "name": "text", "email": "email", "rating": "number",
        "restaurant_id": "select", "message": "textarea",
    }
    # text-field helper excludes hidden/number/select/textarea
    text_fields = f.text_field_names()
    assert "name" in text_fields and "email" in text_fields
    assert "rating" not in text_fields
    assert "restaurant_id" not in text_fields
    # textarea IS treated as text (it's the stored-xss sink shape)
    assert "message" in text_fields


def test_action_defaults_to_blank_for_self_post():
    html = '<form method="post"><input name="x"></form>'
    forms = _parse_forms(html, "http://host:5000/here")
    assert len(forms) == 1
    assert forms[0].action == ""
    assert forms[0].method == "post"


def test_multiple_forms_per_page():
    html = (
        '<form method="post" action="/a"><input name="a1"></form>'
        '<form method="get"  action="/b"><input name="b1"></form>'
    )
    forms = _parse_forms(html, "http://host:5000/")
    assert len(forms) == 2
    assert forms[0].method == "post" and forms[1].method == "get"
    assert forms[0].action.endswith("/a")
    assert forms[1].action.endswith("/b")


def test_empty_html_returns_empty_list():
    assert _parse_forms("", "http://host:5000/") == []
    assert _parse_forms("<html></html>", "http://host:5000/") == []


def test_summarize_ranks_form_endpoints_highest():
    em_form = EndpointMap(
        url="http://host:5000/admin/offer", status=200,
        content_type="text/html",
        forms=[FormSpec(action="http://host:5000/admin/offer", method="post")],
    )
    em_json = EndpointMap(url="http://host:5000/admin/config", status=200,
                          content_type="application/json")
    em_xml = EndpointMap(url="http://host:5000/admin/import", status=405,
                         content_type="text/html", allow="OPTIONS, POST")
    em_boring = EndpointMap(url="http://host:5000/static/x.css", status=200,
                            content_type="text/css")
    out = summarize_for_llm([em_boring, em_xml, em_json, em_form])
    lines = [l for l in out.splitlines() if l.strip()]
    # Boring (zero signal) is dropped
    assert all("/static/" not in l for l in lines)
    # Form endpoint ranks first (highest score)
    assert "/admin/offer" in lines[0]
    # JSON + XML endpoints are included
    assert any("/admin/config" in l for l in lines)
    assert any("/admin/import" in l for l in lines)


def test_summary_line_includes_field_names_for_sink_detection():
    f = FormSpec(action="http://host:5000/admin/offer", method="post",
                 fields=[])
    f.fields.append(type(f.fields)([]) and None)  # noqa — not used
    # rebuild cleanly: parse real HTML so FormField types check cleanly
    html = '<form method="post" action="/admin/offer"><textarea name="offer">x</textarea></form>'
    em = EndpointMap(url="http://host:5000/admin/offer", status=200,
                     content_type="text/html",
                     forms=_parse_forms(html, "http://host:5000/admin/offer"))
    line = em.summary_line()
    assert "offer:textarea" in line, line
