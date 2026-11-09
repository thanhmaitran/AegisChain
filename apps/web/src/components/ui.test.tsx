import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { StatusBadge } from "./ui";

describe("StatusBadge", () => {
  it("renders the status text so colour is never the only signal", () => {
    render(<StatusBadge status="INDETERMINATE" />);
    expect(screen.getByText("INDETERMINATE")).toBeTruthy();
  });
});
