import { LucideIcon } from "lucide-react";
import { Link } from "react-router-dom";
import { cn } from "@/lib/utils";
import { buttonVariants } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

export interface NavLink {
  title: string;
  label?: string;
  icon?: LucideIcon;
  path: string;
  variant: "default" | "ghost";
  children?: NavLink[];
}

interface NavProps {
  isCollapsed: boolean;
  size: "sm" | "lg" | "default";
  links: NavLink[];
}

export function Nav({ links, isCollapsed, size }: NavProps) {
  const generateChildren = (children: NavLink[]) => {
    return children.map((link) => {
      return (
        <Link
          key={link.path}
          to={link.path}
          title={link.title}
          className={cn(
            buttonVariants({ variant: link.variant, size }),
            "px-8 truncate",
            link.variant === "default" &&
              "dark:bg-muted dark:text-white dark:hover:bg-muted dark:hover:text-white",
            "justify-start",
          )}
        >
          {link.title}
        </Link>
      );
    });
  };
  const generateTooltip = (link: NavLink) => {
    return (
      <Tooltip key={link.path} delayDuration={0}>
        <TooltipTrigger asChild>
          <Link
            to={link.path}
            title={link.title}
            className={cn(
              buttonVariants({ variant: link.variant, size: "icon" }),
              "h-9 w-9",
              link.variant === "default" &&
                "dark:bg-muted dark:text-muted-foreground dark:hover:bg-muted dark:hover:text-white",
            )}
          >
            {link.icon && <link.icon className="h-4 w-4" />}
            <span className="sr-only">{link.title}</span>
          </Link>
        </TooltipTrigger>
        <TooltipContent side="right" className="flex items-center gap-4">
          {link.title}
          {link.label && (
            <span className="ml-auto text-muted-foreground">{link.label}</span>
          )}
        </TooltipContent>
      </Tooltip>
    );
  };
  const generateLink = (link: NavLink) => {
    return (
      <Link
        key={link.path}
        to={link.path}
        title={link.title}
        className={cn(
          buttonVariants({ variant: link.variant, size }),
          "px-4",
          link.variant === "default" &&
            "dark:bg-muted dark:text-white dark:hover:bg-muted dark:hover:text-white",
          "justify-start",
        )}
      >
        {link.icon && <link.icon className="mr-2 h-4 w-4" />}
        {link.title}
        {link.label && (
          <span
            className={cn(
              "ml-auto",
              link.variant === "default" && "text-background dark:text-white",
            )}
          >
            {link.label}
          </span>
        )}
      </Link>
    );
  };

  const items: JSX.Element[] = [];
  links.forEach((link) => {
    if (isCollapsed) {
      items.push(generateTooltip(link));
    } else {
      items.push(generateLink(link));
      if (link.children?.length) {
        items.push(...generateChildren(link.children));
      }
    }
  });

  return (
    <div
      data-collapsed={isCollapsed}
      className="group flex flex-col gap-4 py-2 data-[collapsed=true]:py-2"
    >
      <nav className="grid gap-1 px-2 group-[[data-collapsed=true]]:justify-center group-[[data-collapsed=true]]:px-2 truncate">
        {items}
      </nav>
    </div>
  );
}
