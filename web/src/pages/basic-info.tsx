import useConfigStore from "../states/config";
import Loading from "../components/loading";
import FormEditor, {
  FormItem,
  FormItemCategory,
} from "../components/form-editor";

export default function BasicInfo() {
  const [initialized, config, update] = useConfigStore((state) => [
    state.initialized,
    state.data,
    state.update,
  ]);
  if (!initialized) {
    return <Loading />;
  }
  const arr: FormItem[] = [
    {
      id: "pid_file",
      label: "Pid File",
      defaultValue: config.pid_file,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "upgrade_sock",
      label: "Upgrade Sock",
      defaultValue: config.upgrade_sock,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "threads",
      label: "Threads",
      defaultValue: config.threads,
      span: 6,
      category: FormItemCategory.NUMBER,
    },
    {
      id: "user",
      label: "User",
      defaultValue: config.user,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "group",
      label: "Group",
      defaultValue: config.group,
      span: 6,
      category: FormItemCategory.TEXT,
    },
    {
      id: "work_stealing",
      label: "Work Stealing",
      defaultValue: config.work_stealing,
      span: 6,
      category: FormItemCategory.CHECKBOX,
    },
    {
      id: "error_template",
      label: "Error Template",
      defaultValue: config.error_template,
      span: 12,
      minRows: 8,
      category: FormItemCategory.TEXTAREA,
    },
  ];
  const onUpsert = async (name: string, data: Record<string, unknown>) => {
    return update("pingap", "basic", data);
  };
  return (
    <FormEditor
      title="Modify the basic configurations"
      description="The basic configuration of pingap mainly includes various configurations such as logs, graceful restart, threads, etc."
      items={arr}
      onUpsert={onUpsert}
    />
  );
}
