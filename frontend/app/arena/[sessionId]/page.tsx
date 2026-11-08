import { redirect } from "next/navigation";

import { ChatRoom } from "@/components/arena/ChatRoom";
import { getMe } from "@/lib/server-api";

export default async function ChatPage({ params }: { params: Promise<{ sessionId: string }> }) {
  if (!(await getMe())) redirect("/");
  const { sessionId } = await params;
  return (
    <main className="wide">
      <ChatRoom sessionId={sessionId} />
    </main>
  );
}
