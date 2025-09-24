import * as React from "react"
import { cn } from "@/lib/utils"

const Popover = ({ children }: { children: React.ReactNode }) => {
  return <div className="relative">{children}</div>;
};

const PopoverTrigger = ({ children, asChild }: {
  children: React.ReactNode;
  asChild?: boolean;
}) => {
  return <>{children}</>;
};

const PopoverContent = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement> & {
    side?: 'top' | 'right' | 'bottom' | 'left';
    sideOffset?: number;
  }
>(({ className, side = "bottom", sideOffset = 4, ...props }, ref) => (
  <div
    ref={ref}
    className={cn(
      "z-50 w-72 rounded-md border bg-popover p-4 text-popover-foreground shadow-md outline-none",
      className
    )}
    {...props}
  />
))
PopoverContent.displayName = "PopoverContent"

export { Popover, PopoverTrigger, PopoverContent }