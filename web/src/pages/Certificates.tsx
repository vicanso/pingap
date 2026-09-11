import { LoadingPage } from "@/components/loading";
import { useI18n } from "@/i18n";
import useConfigState, {
  Certificate,
  CertificateInfo,
} from "@/states/config";
import { ExForm, ExFormItem } from "@/components/ex-form";
import { z } from "zod";
import {
  ExFormItemCategory,
  newStringOptions,
  newBooleanOptions,
} from "@/constants";
import { omitEmptyArrayString } from "@/helpers/util";
import { useSearchParams } from "react-router-dom";
import { useShallow } from "zustand/react/shallow";
import History from "@/pages/History";
import { EntityBadge } from "@/components/config-entity-badge";
import { PageShell } from "@/components/page-shell";
import {
  ConfigEntityList,
  EntityText,
  type ConfigEntityColumn,
} from "@/components/config-entity-list";
import { ConfigEntitySummary } from "@/components/config-entity-summary";
import { sortIntoSections } from "@/components/ex-form-sections";
import { CERTIFICATES } from "@/routers";
import { Check } from "lucide-react";
import React from "react";

function getCertificateConfig(
  name: string,
  certificates?: Record<string, Certificate>,
) {
  if (!certificates) {
    return {} as Certificate;
  }
  return (certificates[name] || {}) as Certificate;
}

function formatExpiry(notAfter: number) {
  const date = new Date(notAfter * 1000);
  const pad = (n: number) => n.toString().padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

export default function Certificates() {
  const certificateI18n = useI18n("certificate");
  const i18n = useI18n();
  const [searchParams, setSearchParams] = useSearchParams();

  const [config, initialized, update, remove, version, getCertificateInfos] =
    useConfigState(
      useShallow((state) => [
        state.data,
        state.initialized,
        state.update,
        state.remove,
        state.version,
        state.getCertificateInfos,
      ]),
    );
  const [infos, setInfos] = React.useState<Record<string, CertificateInfo>>(
    {},
  );
  React.useEffect(() => {
    if (!initialized) {
      return;
    }
    getCertificateInfos()
      .then(setInfos)
      .catch(() => setInfos({}));
  }, [initialized, getCertificateInfos, version]);

  const newCertificate = "*";
  const certificates = Object.keys(config.certificates || {});
  certificates.sort();
  // No `name` in the url means the category overview, `*` means the create form.
  const currentCertificate = searchParams.get("name") || "";

  if (!initialized) {
    return <LoadingPage />;
  }

  if (!currentCertificate) {
    const values = config.certificates || {};
    const hasDomains = certificates.some((name) =>
      Boolean(values[name]?.domains),
    );
    const hasAcme = certificates.some((name) => Boolean(values[name]?.acme));
    const hasExpiry = certificates.some((name) => Boolean(infos[name]?.not_after));
    const columns: ConfigEntityColumn<Certificate>[] = [];
    if (hasDomains) {
      columns.push({
        key: "domains",
        label: certificateI18n("domains"),
        render: (value) => <EntityText value={value?.domains} />,
      });
    }
    if (hasExpiry) {
      columns.push({
        key: "expires",
        label: certificateI18n("expires"),
        render: (_value, name) => {
          const notAfter = infos[name]?.not_after;
          return (
            <EntityText
              value={notAfter ? formatExpiry(notAfter) : undefined}
            />
          );
        },
      });
    }
    if (hasAcme) {
      columns.push({
        key: "acme",
        label: certificateI18n("acme"),
        render: (value) => <EntityText value={value?.acme} />,
      });
    }
    columns.push({
      key: "isDefault",
      label: certificateI18n("isDefault"),
      render: (value) =>
        value?.is_default ? (
          <Check className="size-4 text-primary" />
        ) : (
          <EntityText />
        ),
    });
    return (
      <ConfigEntityList<Certificate>
        title={certificateI18n("title")}
        summary={certificateI18n("summary", { count: certificates.length })}
        nameLabel={certificateI18n("name")}
        addLabel={certificateI18n("add")}
        emptyText={certificateI18n("empty")}
        basePath={CERTIFICATES}
        newValue={newCertificate}
        names={certificates}
        values={values}
        columns={columns}
      />
    );
  }

  const handleSelectCertificate = (name: string) => {
    searchParams.set("name", name);
    setSearchParams(searchParams);
  };

  const backToList = () => {
    searchParams.delete("name");
    setSearchParams(searchParams);
  };

  const certificateConfig = getCertificateConfig(
    currentCertificate,
    config.certificates,
  );
  const countLines = (value: string) => {
    const count = value.split("\n").length;
    return Math.min(Math.max(3, count), 8);
  };

  const sec = {
    basic: certificateI18n("sectionBasic"),
    pem: certificateI18n("sectionPem"),
  };

  const items: ExFormItem[] = [
    {
      name: "domains",
      section: sec.basic,
      label: certificateI18n("domains"),
      placeholder: certificateI18n("domainsPlaceholder"),
      defaultValue: certificateConfig.domains,
      span: 6,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "acme",
      section: sec.basic,
      label: certificateI18n("acme"),
      placeholder: "",
      defaultValue: certificateConfig.acme,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newStringOptions(["lets_encrypt"], true, true),
    },
    {
      name: "is_default",
      section: sec.basic,
      label: certificateI18n("isDefault"),
      placeholder: "",
      defaultValue: certificateConfig.is_default,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "dns_challenge",
      section: sec.basic,
      label: certificateI18n("dnsChallenge"),
      placeholder: "",
      defaultValue: certificateConfig.dns_challenge,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "dns_provider",
      section: sec.basic,
      label: certificateI18n("dnsProvider"),
      placeholder: "",
      tips: certificateI18n("dnsProviderTips"),
      // Unset selects the "Unset" option, whose empty value is dropped on
      // save, instead of writing dns_provider = "manual" into every
      // certificate that never chose a provider.
      defaultValue: certificateConfig.dns_provider || "",
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newStringOptions(
        ["manual", "ali", "cf", "huawei", "tencent"],
        true,
        true,
      ),
    },
    {
      name: "dns_service_url",
      section: sec.basic,
      label: certificateI18n("dnsServiceUrl"),
      placeholder: certificateI18n("dnsServiceUrlPlaceholder"),
      defaultValue: certificateConfig.dns_service_url,
      span: 3,
      category: ExFormItemCategory.TEXT,
    },
    {
      name: "is_ca",
      section: sec.basic,
      label: certificateI18n("isCa"),
      placeholder: "",
      defaultValue: certificateConfig.is_ca,
      span: 3,
      category: ExFormItemCategory.RADIOS,
      options: newBooleanOptions(),
    },
    {
      name: "buffer_days",
      section: sec.basic,
      label: certificateI18n("bufferDays"),
      placeholder: certificateI18n("bufferDaysPlaceholder"),
      defaultValue: certificateConfig.buffer_days,
      span: 3,
      category: ExFormItemCategory.NUMBER,
    },
    {
      name: "remark",
      section: sec.basic,
      label: certificateI18n("remark"),
      placeholder: "",
      defaultValue: certificateConfig.remark,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
    },
    {
      name: "tls_cert",
      section: sec.pem,
      label: certificateI18n("tlsCert"),
      placeholder: certificateI18n("tlsCertPlaceholder"),
      defaultValue: certificateConfig.tls_cert,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
      rows: countLines(certificateConfig.tls_cert || ""),
      nullAsEmpty: true,
    },
    {
      name: "tls_key",
      section: sec.pem,
      label: certificateI18n("tlsKey"),
      placeholder: certificateI18n("tlsKeyPlaceholder"),
      defaultValue: certificateConfig.tls_key,
      span: 6,
      category: ExFormItemCategory.TEXTAREA,
      rows: countLines(certificateConfig.tls_key || ""),
      nullAsEmpty: true,
    },
  ];

  if (currentCertificate === newCertificate) {
    items.unshift({
      name: "name",
      section: sec.basic,
      label: certificateI18n("name"),
      placeholder: certificateI18n("namePlaceholder"),
      defaultValue: "",
      span: 6,
      category: ExFormItemCategory.TEXT,
    });
  }

  const defaultShow = sortIntoSections(
    items,
    [sec.basic, sec.pem],
    [sec.basic],
  );

  const schema = z.object({});
  const onRemove = async () => {
    return remove("certificate", currentCertificate).then(() => {
      backToList();
    });
  };

  const info = infos[currentCertificate];

  return (
    <PageShell
      eyebrow="certificates"
      title={certificateI18n("title")}
      description={certificateI18n("description")}
      width="narrow"
      backTo={CERTIFICATES}
      backLabel={i18n("backToList")}
      badge={
        <EntityBadge
          name={currentCertificate}
          isNew={currentCertificate === newCertificate}
        />
      }
      actions={
        currentCertificate !== newCertificate ? (
          <History
            category="certificate"
            name={currentCertificate}
            onRestore={async (data) => {
              await update("certificate", currentCertificate, data);
            }}
          />
        ) : undefined
      }
    >
      {currentCertificate !== newCertificate && (
        <ConfigEntitySummary
          fields={[
            {
              label: certificateI18n("domains"),
              value: certificateConfig.domains || undefined,
              mono: true,
            },
            {
              label: certificateI18n("expires"),
              value: info?.not_after
                ? formatExpiry(info.not_after)
                : undefined,
              mono: true,
            },
            {
              label: certificateI18n("acme"),
              value: certificateConfig.acme || undefined,
            },
            {
              label: certificateI18n("isDefault"),
              value: certificateConfig.is_default
                ? certificateI18n("yes")
                : undefined,
            },
            {
              label: certificateI18n("tlsCert"),
              value: certificateConfig.tls_cert
                ? certificateI18n("pemConfigured")
                : undefined,
            },
          ]}
        />
      )}
      <ExForm
        category="certificate"
        key={`${currentCertificate}-${version}`}
        items={items}
        schema={schema}
        defaultShow={defaultShow}
        onRemove={
          currentCertificate === newCertificate ? undefined : onRemove
        }
        onSave={async (value) => {
          let name = currentCertificate;
          if (name === newCertificate) {
            name = value["name"] as string;
          }
          // The form only carries the fields it shows, and the server replaces
          // the whole entry with what it receives. Start from the loaded entry
          // so fields the form has no item for survive a save. Merged before
          // empty values are dropped, so a field cleared in the form is still
          // removed.
          const data = {
            ...(config.certificates || {})[currentCertificate],
            ...value,
          };
          omitEmptyArrayString(data);
          await update("certificate", name, data);
          handleSelectCertificate(name);
        }}
      />
    </PageShell>
  );
}
