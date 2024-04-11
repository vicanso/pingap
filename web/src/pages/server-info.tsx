import useConfigStore from "../states/config";
import { useParams } from "react-router-dom";

import Loading from "../components/loading";
import FormEditor, {
  FormItem,
  FormItemCategory,
} from "../components/form-editor";

export default function ServerInfo() {
  const [initialized, config, update] = useConfigStore((state) => [
    state.initialized,
    state.data,
    state.update,
  ]);
  const { name } = useParams();
  if (!initialized) {
    return <Loading />;
  }
  let created = false;
  let serverName = name;
  if (name == "*") {
    created = true;
    serverName = "";
  }
  const servers = config.servers || {};
  const currentNames = Object.keys(servers);
  const server = servers[serverName || ""] || {};
  const locations = Object.keys(config.locations || {});

  const arr: FormItem[] = [
    {
      id: "addr",
      label: "Listen Address",
      defaultValue: server.addr,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "locations",
      label: "Locations",
      defaultValue: server.locations,
      span: 6,
      category: FormItemCategory.LOCATION,
      options: locations,
    },
    {
      id: "stats_path",
      label: "Stats Path",
      defaultValue: server.stats_path,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "admin_path",
      label: "Admin Path",
      defaultValue: server.admin_path,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "access_log",
      label: "Access Log",
      defaultValue: server.access_log,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "threads",
      label: "Threads",
      defaultValue: server.threads,
      span: 6,
      category: FormItemCategory.NUMBER,
    },
    {
      id: "tls_cert",
      label: "Tls Cert(base64)",
      defaultValue: server.tls_cert,
      span: 12,
      category: FormItemCategory.TEXTAREA,
    },
    {
      id: "tls_key",
      label: "Tls Key(base64)",
      defaultValue: server.tls_key,
      span: 12,
      category: FormItemCategory.TEXTAREA,
    },
    {
      id: "remark",
      label: "Remark",
      defaultValue: server.remark,
      span: 12,
      category: FormItemCategory.TEXTAREA,
    },
  ];

  const onUpsert = async (newName: string, data: Record<string, unknown>) => {
    let serverName = name || "";
    if (created) {
      serverName = newName;
    }
    return update("server", serverName, data);
  };
  return (
    <FormEditor
      key={name}
      title="Modify server configuration"
      description="Change the server configuration"
      items={arr}
      onUpsert={onUpsert}
      created={created}
      currentNames={currentNames}
    />
  );
}
