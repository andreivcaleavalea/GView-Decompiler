#include "pe.hpp"

using namespace AppCUI::Controls;

namespace GView::Type::PE::Panels
{
Decompiler::Decompiler(Reference<Object> _object, Reference<GView::Type::PE::PEFile> _pe) : TabPage("&Decompiler"), pe(_pe), object(_object)
{
    Update();
    output = Factory::TextArea::Create(
          this, text, "d:c", TextAreaFlags::Readonly | TextAreaFlags::ScrollBars | TextAreaFlags::ShowLineNumbers | TextAreaFlags::SyntaxHighlighting);
}

void Decompiler::Update()
{
    text = DecompilerAdapter::BuildFunctionsText(object, pe);
}
} // namespace GView::Type::PE::Panels
