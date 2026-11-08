// SHELL ONLY. Real quizzes never ship answers to the browser before the student answers (E-60);
// Phase C replaces this with POST .../answer, which returns one question's result at a time.

export const MOCK_KEY: Record<string, { answerIndex: number; explanation: string }> = {
  q1: { answerIndex: 1, explanation: "The bot followed instructions hidden in the poisoned document." },
  q2: { answerIndex: 0, explanation: "It treated tool output as if the teacher had written it." },
  q3: { answerIndex: 2, explanation: "The judge scored the email call high, so the Gatekeeper denied it." },
  q4: { answerIndex: 1, explanation: "Treat documents as data and restrict who the bot can email." },
  q5: { answerIndex: 1, explanation: "Diverts look like success; an answer that is too convenient is a clue." },
};
