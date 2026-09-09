# DQ Gate Demo

This project demonstrates the DQ Gate policy using two MCP connectors:

- **Property A** — high data quality (DQ score 90, passes the 80 threshold)
- **Property B** — low data quality (DQ score 70, blocked by the 80 threshold)

When referencing these connectors in responses, always use "Property A" and "Property B" instead of their internal connector names.