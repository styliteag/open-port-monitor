import { describe, it, expect } from "vitest";
import { render, screen } from "@testing-library/react";

import { SplitView } from "./SplitView";

describe("SplitView", () => {
  it("renders list and detail content", () => {
    render(<SplitView list={<p>list content</p>} detail={<p>detail content</p>} />);
    expect(screen.getByText("list content")).toBeInTheDocument();
    expect(screen.getByText("detail content")).toBeInTheDocument();
  });

  it("puts content into the correct panes", () => {
    render(<SplitView list={<p>the list</p>} detail={<p>the detail</p>} />);
    expect(screen.getByTestId("split-view-list")).toHaveTextContent("the list");
    expect(screen.getByTestId("split-view-detail")).toHaveTextContent(
      "the detail",
    );
  });
});
