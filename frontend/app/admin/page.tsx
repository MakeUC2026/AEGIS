import { redirect } from "next/navigation";

// The console opens on the review queue; its other screens are tabs on each page.
export default function Page() {
  redirect("/admin/review");
}
