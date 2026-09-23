import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, Campaign, Engagement } from "../api/client";

export default function Campaigns() {
  const navigate = useNavigate();
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [engagements, setEngagements] = useState<Engagement[]>([]);
  const [sessionName, setSessionName] = useState<Record<string, string>>({});
  const [error, setError] = useState<string | null>(null);
  const [running, setRunning] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([api.listCampaigns(), api.listEngagements()])
      .then(([c, e]) => {
        setCampaigns(c);
        setEngagements(e);
      })
      .catch((e) => setError(String(e)));
  }, []);

  const run = (name: string) => {
    setRunning(name);
    setError(null);
    api
      .runCampaign(name, sessionName[name] || undefined)
      .then((created) => navigate(`/campaigns/runs/${created.job_id}/live`))
      .catch((e) => setError(String(e)))
      .finally(() => setRunning(null));
  };

  const engagementFor = (name: string) => engagements.find((e) => e.name === name);

  return (
    <div>
      <h2>Campaigns</h2>
      <p className="muted">
        登録済みのEngagement(複数targetのグループ)に対して、1つのPlaybookを一括実行します。
        どのtargetにどのPlaybookを回すかは人間が事前に書いた <code>config/campaigns/*.yaml</code> で決まり、
        実行時にAIが対象や手順を選ぶことはありません。完了後、各targetの成功したrunが新しいAttack Sessionのstageとして自動登録されます。
      </p>
      {error && <p className="error">{error}</p>}
      {campaigns.length === 0 && (
        <p className="muted">
          利用可能なCampaignがありません。<code>config/campaigns/*.yaml</code> を追加してください。
        </p>
      )}

      {campaigns.map((campaign) => {
        const engagement = engagementFor(campaign.engagement);
        return (
          <div key={campaign.name} className="card">
            <h3>{campaign.name}</h3>
            <p className="muted">{campaign.description}</p>
            <p>
              Engagement: <code>{campaign.engagement}</code>{" "}
              {engagement ? (
                <span className="muted">({engagement.targets.join(", ")})</span>
              ) : (
                <span className="error">未登録(pownforge engagement addが必要)</span>
              )}
            </p>
            <p>
              Playbook: <code>{campaign.playbook}</code>
            </p>
            <div className="option-row">
              <input
                type="text"
                placeholder="Attack Session名(省略可)"
                value={sessionName[campaign.name] ?? ""}
                onChange={(e) =>
                  setSessionName((prev) => ({ ...prev, [campaign.name]: e.target.value }))
                }
              />
              <button
                type="button"
                disabled={!engagement || engagement.targets.length === 0 || running === campaign.name}
                onClick={() => run(campaign.name)}
              >
                {running === campaign.name ? "開始中..." : "実行"}
              </button>
            </div>
          </div>
        );
      })}
    </div>
  );
}
