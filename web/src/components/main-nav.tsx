import * as React from "react";
import ListSubheader from "@mui/material/ListSubheader";
import List from "@mui/material/List";
import ListItemButton from "@mui/material/ListItemButton";
import ListItemIcon from "@mui/material/ListItemIcon";
import ListItemText from "@mui/material/ListItemText";
import Collapse from "@mui/material/Collapse";
import NetworkPingIcon from "@mui/icons-material/NetworkPing";
import ExpandLess from "@mui/icons-material/ExpandLess";
import ExpandMore from "@mui/icons-material/ExpandMore";
import GpsFixedIcon from "@mui/icons-material/GpsFixed";
import DnsIcon from "@mui/icons-material/Dns";
import DashboardIcon from "@mui/icons-material/Dashboard";
import Snackbar from "@mui/material/Snackbar";
import { useAsync } from "react-async-hook";
import useConfigStore from "../states/config";
import {
  goToBasicInfo,
  goToServerInfo,
  goToLoationInfo,
  goToUpstreamInfo,
} from "../router";
import { formatError } from "../helpers/util";

enum NavCategory {
  BasicInfo,
  ServerInfo,
  LocationInfo,
  UpstreamInfo,
}

interface NavItem {
  name: string;
  icon: JSX.Element;
  children: string[];
  category: NavCategory;
}

export default function MainNav() {
  const [opens, setOpens] = React.useState([] as Number[]);
  const [navItems, setNavItems] = React.useState([] as NavItem[]);
  const [fetch] = useConfigStore((state) => [state.fetch]);
  const [showError, setShowError] = React.useState({
    open: false,
    message: "",
  });

  useAsync(async () => {
    try {
      const config = await fetch();
      const items: NavItem[] = [];
      items.push({
        name: "Pingap",
        icon: <DashboardIcon />,
        children: [],
        category: NavCategory.BasicInfo,
      });
      items.push({
        name: "Server",
        icon: <DnsIcon />,
        children: Object.keys(config.servers || {}),
        category: NavCategory.ServerInfo,
      });
      items.push({
        name: "Location",
        icon: <GpsFixedIcon />,
        children: Object.keys(config.locations || {}),
        category: NavCategory.LocationInfo,
      });
      items.push({
        name: "Upstream",
        icon: <NetworkPingIcon />,
        children: Object.keys(config.upstreams || {}),
        category: NavCategory.UpstreamInfo,
      });
      setNavItems(items);
    } catch (err) {
      setShowError({
        open: true,
        message: formatError(err),
      });
      // TODO error handle
    } finally {
    }
  }, []);

  const toggleCollapse = (index: number) => {
    const values = opens.slice(0);
    const value = values.indexOf(index);
    if (value >= 0) {
      values.splice(value, 1);
    } else {
      values.push(index);
    }
    setOpens(values);
  };

  const list: JSX.Element[] = [];
  navItems.forEach((item, index) => {
    const exits_children = item.children.length != 0;
    let expand = <></>;
    if (exits_children) {
      if (opens.includes(index)) {
        expand = <ExpandLess />;
      } else {
        expand = <ExpandMore />;
      }
    }

    list.push(
      <ListItemButton
        key={item.name}
        onClick={() => {
          if (item.category == NavCategory.BasicInfo) {
            goToBasicInfo();
            return;
          }
          toggleCollapse(index);
        }}
      >
        <ListItemIcon>{item.icon}</ListItemIcon>
        <ListItemText primary={item.name} />
        {expand}
      </ListItemButton>,
    );
    if (exits_children) {
      const subItems = item.children.map((name) => {
        return (
          <ListItemButton
            sx={{ pl: 4 }}
            key={`${item.name}-sub-${name}`}
            onClick={() => {
              switch (item.category) {
                case NavCategory.ServerInfo: {
                  goToServerInfo(name);
                  break;
                }
                case NavCategory.LocationInfo: {
                  goToLoationInfo(name);
                  break;
                }
                case NavCategory.UpstreamInfo: {
                  goToUpstreamInfo(name);
                  break;
                }
              }
            }}
          >
            <ListItemText primary={name} />
          </ListItemButton>
        );
      });
      list.push(
        <Collapse
          key={`${item.name}-sub`}
          in={opens.includes(index)}
          timeout="auto"
          unmountOnExit
        >
          <List component="div" disablePadding>
            {subItems}
          </List>
        </Collapse>,
      );
    }
  });

  return (
    <React.Fragment>
      <List
        sx={{ width: 260, bgcolor: "background.paper" }}
        component="nav"
        aria-labelledby="nested-list-subheader"
        subheader={
          <ListSubheader component="div" id="nested-list-subheader">
            Pingap
          </ListSubheader>
        }
      >
        {list}
      </List>
      <Snackbar
        open={showError.open}
        autoHideDuration={6000}
        onClose={() => {
          setShowError({
            open: false,
            message: "",
          });
        }}
        message={showError.message}
      />
    </React.Fragment>
  );
}
