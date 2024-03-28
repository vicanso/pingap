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
  const servers = config.servers || {};
  const server = servers[name || ""];
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
      id: "access_log",
      label: "Access Log",
      defaultValue: server.access_log,
      span: 12,
      category: FormItemCategory.TEXT,
    },
    {
      id: "tls_cert",
      label: "Tls Cert(base64)",
      defaultValue: server.tls_cert,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "tls_key",
      label: "Tls Key(base64)",
      defaultValue: server.tls_key,
      span: 6,
      category: FormItemCategory.TEXT,
    },
  ];

  const onUpsert = async (_: string, data: Record<string, unknown>) => {
    return update("server", name || "", data);
  };
  return (
    <FormEditor
      key={name}
      title="Modify server configuration"
      description="Change the server configuration"
      items={arr}
      onUpsert={onUpsert}
    />
  );
}
