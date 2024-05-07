import * as React from "react";
import List from "@mui/material/List";
import ListItemButton from "@mui/material/ListItemButton";
import ListItemIcon from "@mui/material/ListItemIcon";
import ListItemText from "@mui/material/ListItemText";
import Collapse from "@mui/material/Collapse";
import ExpandLess from "@mui/icons-material/ExpandLess";
import ExpandMore from "@mui/icons-material/ExpandMore";
import DnsIcon from "@mui/icons-material/Dns";
import DashboardIcon from "@mui/icons-material/Dashboard";
import Snackbar from "@mui/material/Snackbar";
import AddRoadIcon from "@mui/icons-material/AddRoad";
import AccountTreeIcon from "@mui/icons-material/AccountTree";
import AltRouteIcon from "@mui/icons-material/AltRoute";
import ExtensionIcon from "@mui/icons-material/Extension";
import Button from "@mui/material/Button";
import { useTranslation } from "react-i18next";
import { useAsync } from "react-async-hook";
import useConfigStore from "../states/config";
import {
  goToBasicInfo,
  goToServerInfo,
  goToLoationInfo,
  goToUpstreamInfo,
  goToProxyPluginInfo,
} from "../router";
import { formatError } from "../helpers/util";

enum NavCategory {
  BasicInfo,
  ServerInfo,
  LocationInfo,
  UpstreamInfo,
  ProxyPluginInfo,
}

interface NavItem {
  name: string;
  icon: JSX.Element;
  children: string[];
  category: NavCategory;
}

export default function MainNav({
  navWidth,
  navTop,
}: {
  navWidth: string;
  navTop: string;
}) {
  const { t } = useTranslation();

  const [opens, setOpens] = React.useState([] as Number[]);
  const [navItems, setNavItems] = React.useState([] as NavItem[]);
  const [mainSelectedIndex, setMainSelectedIndex] = React.useState(-1);
  const [subSelectedIndex, setSubSelectedIndex] = React.useState(-1);
  const [fetch, configVersion] = useConfigStore((state) => [
    state.fetch,
    state.version,
  ]);
  const [showError, setShowError] = React.useState({
    open: false,
    message: "",
  });
  const addTag = "*";

  useAsync(async () => {
    try {
      const config = await fetch();
      const items: NavItem[] = [];
      items.push({
        name: t("nav.basic"),
        icon: <DashboardIcon />,
        children: [],
        category: NavCategory.BasicInfo,
      });
      const servers = Object.keys(config.servers || {}).sort();
      servers.push(addTag);
      items.push({
        name: t("nav.server"),
        icon: <DnsIcon />,
        children: servers,
        category: NavCategory.ServerInfo,
      });
      const locations = Object.keys(config.locations || {}).sort();
      locations.push(addTag);
      items.push({
        name: t("nav.location"),
        icon: <AccountTreeIcon />,
        children: locations,
        category: NavCategory.LocationInfo,
      });
      const upstreams = Object.keys(config.upstreams || {}).sort();
      upstreams.push(addTag);
      items.push({
        name: t("nav.upstream"),
        icon: <AltRouteIcon />,
        children: upstreams,
        category: NavCategory.UpstreamInfo,
      });

      const proxyPluins = Object.keys(config.proxy_plugins || {}).sort();
      proxyPluins.push(addTag);
      items.push({
        name: t("nav.proxyPlugin"),
        icon: <ExtensionIcon />,
        children: proxyPluins,
        category: NavCategory.ProxyPluginInfo,
      });
      setNavItems(items);
    } catch (err) {
      setShowError({
        open: true,
        message: formatError(err),
      });
    }
  }, [configVersion]);

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
          setMainSelectedIndex(index);
          setSubSelectedIndex(-1);
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
      const subItems = item.children.map((name, subIndex) => {
        let itemText = <ListItemText primary={name} />;
        if (name == addTag) {
          itemText = (
            <ListItemText>
              <Button fullWidth variant="outlined" endIcon={<AddRoadIcon />}>
                Add {item.name}
              </Button>
            </ListItemText>
          );
        }
        return (
          <ListItemButton
            selected={
              mainSelectedIndex == index && subSelectedIndex == subIndex
            }
            sx={{ pl: 4 }}
            key={`${item.name}-sub-${name}`}
            onClick={() => {
              setMainSelectedIndex(index);
              setSubSelectedIndex(subIndex);
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
                case NavCategory.ProxyPluginInfo: {
                  goToProxyPluginInfo(name);
                  break;
                }
              }
            }}
          >
            {itemText}
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
    <div
      style={{
        position: "fixed",
        left: 0,
        width: navWidth,
        bottom: 0,
        top: navTop,
        overflowY: "scroll",
      }}
    >
      <List
        sx={{ width: navWidth, bgcolor: "background.paper" }}
        component="nav"
        aria-labelledby="nested-list-subheader"
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
    </div>
  );
}
