// protect-mcp: one deployment per role. Its HTTP mode authenticates a single shared bearer token
// (PROTECT_MCP_HTTP_TOKEN), so Cedar's principal is the deployment, not the end user: this file is
// the venue project_manager role (door_staff tools included), with mcp-rbac's argument limits.
@id("pm.tools")
permit (principal, action == Action::"MCP::Tool::call", resource)
when {
  [Tool::"list_events", Tool::"get_event", Tool::"create_event", Tool::"update_event",
   Tool::"list_tickets", Tool::"get_ticket", Tool::"check_in", Tool::"undo_check_in", Tool::"refund_ticket",
   Tool::"list_bookings", Tool::"create_booking", Tool::"cancel_booking", Tool::"list_booth_spaces",
   Tool::"book_booth_space", Tool::"release_booth_space", Tool::"list_vendors", Tool::"export_guest_list",
   Tool::"get_sales_report"].contains(resource)
};

@id("pm.refund-cap")
@reason("refund over the project_manager cap ($500)")
forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"refund_ticket")
when { !(context has input) || !(context.input has amount) || context.input.amount > 500 };

@id("pm.capacity")
@reason("capacity out of range 1..5000")
forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"create_event")
when { context has input && context.input has capacity && (context.input.capacity < 1 || context.input.capacity > 5000) };

@id("pm.party-size")
@reason("party_size out of range 1..40")
forbid (principal, action == Action::"MCP::Tool::call", resource == Tool::"create_booking")
when { context has input && context.input has party_size && (context.input.party_size < 1 || context.input.party_size > 40) };
